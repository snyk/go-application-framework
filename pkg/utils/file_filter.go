package utils

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/rs/zerolog"
	gitignore "github.com/sabhiram/go-gitignore"
	"golang.org/x/sync/semaphore"
	"gopkg.in/yaml.v3"
)

// by default, all rules are valid
var defaultInvalidRules = []string{}

type FileFilter struct {
	path         string
	defaultRules []string
	logger       *zerolog.Logger
	max_threads  int64
}

type FileFilterOption func(*FileFilter) error

func WithThreadNumber(maxThreadCount int) FileFilterOption {
	return func(filter *FileFilter) error {
		if maxThreadCount > 0 {
			filter.max_threads = int64(maxThreadCount)
			return nil
		}

		return fmt.Errorf("max thread count must be greater than 0")
	}
}

func NewFileFilter(path string, logger *zerolog.Logger, options ...FileFilterOption) *FileFilter {
	filter := &FileFilter{
		path:         path,
		defaultRules: []string{"**/.git/**"},
		logger:       logger,
		max_threads:  int64(runtime.NumCPU()),
	}

	for _, option := range options {
		err := option(filter)
		if err != nil {
			logger.Err(err).Msg("failed to apply option for FileFilter")
		}
	}

	return filter
}

// GetAllFiles traverses a given dir path and fetches all filesToFilter in the directory
func (fw *FileFilter) GetAllFiles() chan string {
	var filesCh = make(chan string)
	go func() {
		defer close(filesCh)

		err := filepath.WalkDir(fw.path, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if !d.IsDir() {
				filesCh <- path
			}

			return err
		})
		if err != nil {
			fw.logger.Error().Msgf("walk dir failed: %v", err)
		}
	}()

	return filesCh
}

// GetRules builds a list of glob patterns that can be used to filter filesToFilter
func (fw *FileFilter) GetRules(ruleFiles []string) ([]string, error) {
	files := fw.GetAllFiles()

	// iterate filesToFilter channel and find ignore filesToFilter
	var ignoreFiles = make([]string, 0)
	for file := range files {
		fileName := filepath.Base(file)
		for _, ruleFile := range ruleFiles {
			if fileName == ruleFile {
				ignoreFiles = append(ignoreFiles, file)
			}
		}
	}

	// iterate ignore filesToFilter and extract glob patterns
	globs, err := fw.buildGlobs(ignoreFiles)
	if err != nil {
		return nil, err
	}

	return append(fw.defaultRules, globs...), nil
}

// GetFilteredFiles returns a filtered channel of filepaths from a given channel of filespaths and glob patterns to filter on
func (fw *FileFilter) GetFilteredFiles(filesCh chan string, globs []string) chan string {
	var filteredFilesCh = make(chan string)

	// create pattern matcher used to match filesToFilter to glob patterns
	globPatternMatcher := gitignore.CompileIgnoreLines(globs...)
	go func() {
		ctx := context.Background()
		availableThreads := semaphore.NewWeighted(fw.max_threads)

		defer close(filteredFilesCh)

		// iterate the filesToFilter channel
		for file := range filesCh {
			err := availableThreads.Acquire(ctx, 1)
			if err != nil {
				fw.logger.Err(err).Msg("failed to limit threads")
			}
			go func(f string) {
				defer availableThreads.Release(1)
				// filesToFilter that do not match the glob pattern are filtered
				if !globPatternMatcher.MatchesPath(f) {
					filteredFilesCh <- f
				}
			}(file)
		}

		// wait until the last thread is done
		err := availableThreads.Acquire(ctx, fw.max_threads)
		if err != nil {
			fw.logger.Err(err).Msg("failed to wait for all threads")
		}
	}()

	return filteredFilesCh
}

// buildGlobs iterates a list of ignore filesToFilter and returns a list of glob patterns that can be used to test for ignored filesToFilter
func (fw *FileFilter) buildGlobs(ignoreFiles []string) ([]string, error) {
	var globs = make([]string, 0)
	for _, ignoreFile := range ignoreFiles {
		parsedRules, err := fw.globsForIgnoreFile(ignoreFile)
		if err != nil {
			return nil, err
		}
		globs = append(globs, parsedRules...)
	}

	return globs, nil
}

// globsForIgnoreFile reads a single ignore file and returns the glob patterns it
// contributes. .snyk files are YAML and parsed differently from .gitignore-style
// files.
func (fw *FileFilter) globsForIgnoreFile(ignoreFile string) ([]string, error) {
	content, err := os.ReadFile(ignoreFile)
	if err != nil {
		return nil, err
	}

	if filepath.Base(ignoreFile) == ".snyk" {
		return fw.parseDotSnykFile(content, filepath.Dir(ignoreFile)), nil
	}
	return parseIgnoreFile(content, filepath.Dir(ignoreFile)), nil
}

// GetFilteredFilesSingleWalk traverses the directory tree exactly once, reading
// ignore files (ruleFiles, e.g. .gitignore/.dcignore/.snyk) as it descends and
// pruning any directory that the rules exclude in its entirety.
//
// This replaces the GetAllFiles + GetRules + GetFilteredFiles pipeline, which
// walked the whole tree twice and glob-matched every file — including everything
// under ignored directories such as node_modules and .git. By pruning excluded
// directories we never descend into them, which is where almost all of the time
// on real projects was being spent.
//
// Correctness: a directory is only pruned when a rule excludes the *directory
// itself* (e.g. `node_modules`, `/node_modules/`, `**/dist`) — never when a rule
// only excludes its contents (e.g. `src/*`, `obj/**`), because those are exactly
// the cases where a `!` negation may re-include files within. A directory that
// contains its own ignore file is also never pruned, since that file may negate.
// Per-file emission still uses the full rule set, so the output is identical to
// the original pipeline. Rules are applied hierarchically; within a directory,
// dotfiles such as .gitignore are visited before normal entries, so ignore rules
// take effect before sibling directories are evaluated for pruning.
func (fw *FileFilter) GetFilteredFilesSingleWalk(ruleFiles []string) chan string {
	filteredFilesCh := make(chan string)

	ruleFileSet := make(map[string]struct{}, len(ruleFiles))
	for _, rf := range ruleFiles {
		ruleFileSet[rf] = struct{}{}
	}

	go func() {
		defer close(filteredFilesCh)

		// dirGlobs/dirMatcher decide which directories are safe to prune (only
		// whole-directory exclusions). The matcher is rebuilt only when a new
		// directory rule is discovered, not on every file. fileGlobs accumulates
		// every rule so the final per-file decision is compiled once, matching the
		// original pipeline exactly.
		dirGlobs := append([]string{}, fw.defaultRules...)
		dirMatcher := gitignore.CompileIgnoreLines(dirGlobs...)
		fileGlobs := append([]string{}, fw.defaultRules...)
		var candidates []string

		err := filepath.WalkDir(fw.path, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}

			if d.IsDir() {
				if path != fw.path &&
					dirMatcher.MatchesPath(path) &&
					!fw.dirContainsRuleFile(path, ruleFileSet) {
					return fs.SkipDir
				}
				return nil
			}

			// Fold ignore-file rules. Directory-exclusion rules update dirMatcher
			// immediately so sibling directories (visited after the dotfile) can be
			// pruned; full rules are accumulated for the single final compile.
			if _, ok := ruleFileSet[d.Name()]; ok {
				fw.foldIgnoreFile(path, &fileGlobs, &dirGlobs, &dirMatcher)
				// Ignore files are themselves scannable.
			}

			candidates = append(candidates, path)
			return nil
		})
		if err != nil {
			fw.logger.Error().Msgf("walk dir failed: %v", err)
		}

		fw.emitCandidates(candidates, fileGlobs, filteredFilesCh)
	}()

	return filteredFilesCh
}

// foldIgnoreFile incorporates the rules from a discovered ignore file: every rule
// is appended to fileGlobs for the final per-file compile, while whole-directory
// exclusions additionally update dirGlobs/dirMatcher so sibling directories
// (visited after the dotfile) can be pruned immediately.
func (fw *FileFilter) foldIgnoreFile(path string, fileGlobs, dirGlobs *[]string, dirMatcher **gitignore.GitIgnore) {
	if newGlobs, gErr := fw.globsForIgnoreFile(path); gErr == nil {
		*fileGlobs = append(*fileGlobs, newGlobs...)
	} else {
		fw.logger.Error().Msgf("failed to read ignore file %s: %v", path, gErr)
	}
	// .snyk is intentionally excluded from dir pruning (its excludes are honored
	// per-file below); only .gitignore-style files contribute whole-directory
	// exclusions.
	if filepath.Base(path) == ".snyk" {
		return
	}
	if dirOnly := fw.dirExclusionGlobs(path); len(dirOnly) > 0 {
		*dirGlobs = append(*dirGlobs, dirOnly...)
		*dirMatcher = gitignore.CompileIgnoreLines(*dirGlobs...)
	}
}

// emitCandidates compiles the full rule set once and emits the surviving files on
// ch. Pruning has already removed everything under wholly-excluded directories, so
// only a small candidate set remains. Matching against the (potentially large)
// rule set is the dominant cost, so it is parallelised across max_threads like the
// original GetFilteredFiles. MatchesPath is read-only and safe for concurrent use.
func (fw *FileFilter) emitCandidates(candidates, fileGlobs []string, ch chan string) {
	fileMatcher := gitignore.CompileIgnoreLines(fileGlobs...)
	ctx := context.Background()
	availableThreads := semaphore.NewWeighted(fw.max_threads)
	for _, f := range candidates {
		if acqErr := availableThreads.Acquire(ctx, 1); acqErr != nil {
			fw.logger.Err(acqErr).Msg("failed to limit threads")
		}
		go func(f string) {
			defer availableThreads.Release(1)
			if !fileMatcher.MatchesPath(f) {
				ch <- f
			}
		}(f)
	}
	// Wait for all in-flight matches to finish before returning.
	if acqErr := availableThreads.Acquire(ctx, fw.max_threads); acqErr != nil {
		fw.logger.Err(acqErr).Msg("failed to wait for all threads")
	}
}

// dirExclusionGlobs reads a .gitignore-style file and returns globs that match a
// directory *as a whole* (so it is safe to prune). Content-only rules (`dir/*`,
// `dir/**`) are deliberately excluded, because a later `!` negation can re-include
// files beneath such a directory. Negation rules are preserved so that `!dir`
// correctly un-prunes a directory.
func (fw *FileFilter) dirExclusionGlobs(ignoreFile string) []string {
	content, err := os.ReadFile(ignoreFile)
	if err != nil {
		return nil
	}
	baseDir := filepath.Dir(ignoreFile)
	var globs []string
	for _, line := range strings.Split(string(content), "\n") {
		if g, ok := dirExclusionGlob(line, baseDir); ok {
			globs = append(globs, g)
		}
	}
	return globs
}

// dirExclusionGlob converts a single .gitignore rule into a glob that matches the
// directory it excludes, or returns ok=false if the rule does not exclude a whole
// directory (blank/comment, or a content-only rule ending in `/*` or `/**`).
func dirExclusionGlob(rule, baseDir string) (string, bool) {
	r := strings.TrimSpace(rule)
	if r == "" || strings.HasPrefix(r, "#") {
		return "", false
	}

	negation := strings.HasPrefix(r, "!")
	if negation {
		r = r[1:]
	}

	// Normalise trailing slashes first so directory rules like `obj/**/` are
	// recognized as the content-only rule `obj/**` below.
	r = strings.TrimRight(r, "/")
	if r == "" {
		return "", false
	}
	// Content-only rules exclude what's *inside* the directory, not the directory
	// itself, so they must not trigger pruning (a `!` may re-include within).
	if strings.HasSuffix(r, "/*") || strings.HasSuffix(r, "/**") {
		return "", false
	}

	base := filepath.ToSlash(baseDir)
	var glob string
	if strings.HasPrefix(r, "/") || strings.HasPrefix(r, "**") {
		// anchored to the ignore file's directory
		glob = filepath.ToSlash(filepath.Join(base, r))
	} else {
		// applies in this directory and any subdirectory
		glob = filepath.ToSlash(filepath.Join(base, "**", r))
	}
	glob = escapeSpecialGlobChars(glob)
	if negation {
		glob = "!" + glob
	}
	return glob, true
}

// dirContainsRuleFile reports whether dir directly contains any of the given
// ignore files. Used to decide whether an ignored directory is safe to prune:
// a directory with its own ignore file may re-include (negate) files inside it.
func (fw *FileFilter) dirContainsRuleFile(dir string, ruleFileSet map[string]struct{}) bool {
	for ruleFile := range ruleFileSet {
		if _, err := os.Stat(filepath.Join(dir, ruleFile)); err == nil {
			return true
		}
	}
	return false
}

// parseDotSnykFile builds a list of glob patterns from a given .snyk style file
func (fw *FileFilter) parseDotSnykFile(content []byte, filePath string) []string {
	type DotSnykRule struct {
		Exclude struct {
			Code   []dotSnykExclude `yaml:"code"`
			Global []dotSnykExclude `yaml:"global"`
		} `yaml:"exclude"`
	}

	var rules DotSnykRule
	err := yaml.Unmarshal(content, &rules)
	if err != nil {
		fw.logger.Error().Msgf("parse .snyk failed: %v", err)
		return nil
	}

	// combine code and global rules
	allRules := append(rules.Exclude.Code, rules.Exclude.Global...)

	var globs []string
	for _, rule := range allRules {
		isExpired, err := rule.IsExpired()

		// treat invalid expires as not expired
		if err != nil {
			fw.logger.Error().Msgf("parse .snyk expires: %v", err)
		}

		if isExpired {
			continue
		}

		// skip absolute paths as they're only relevant for a local file system
		if filepath.IsAbs(rule.Path) {
			fw.logger.Warn().Msgf("Absolute paths are currently not supported when excluding files (%s)", rule.Path)
			continue
		}

		globs = append(globs, parseIgnoreRuleToGlobs(rule.Path, filePath, defaultInvalidRules)...)
	}
	return globs
}

type dotSnykExclude struct {
	Path       string
	expireTime time.Time
	parseError error
}

// newDotSnykExclude creates a new dotSnykExclude with parsed expiry time
func newDotSnykExclude(path string, expiresStr string) dotSnykExclude {
	expireTime, parseError := parseExpireTime(expiresStr)
	return dotSnykExclude{
		Path:       path,
		expireTime: expireTime,
		parseError: parseError,
	}
}

// IsExpired returns true if the exclude rule is expired
func (dse *dotSnykExclude) IsExpired() (expired bool, err error) {
	if dse.parseError != nil {
		return false, dse.parseError
	}

	if dse.expireTime.IsZero() {
		return false, nil
	}

	return time.Now().After(dse.expireTime), nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface
// It correctly unmarshals a .snyk style exclude rule
func (dse *dotSnykExclude) UnmarshalYAML(d *yaml.Node) error {
	if d == nil {
		return nil
	}

	// handle scalar format: "- /path/to/file"
	if d.Kind == yaml.ScalarNode {
		*dse = newDotSnykExclude(d.Value, "")
		return nil
	}

	// handle map format: "- /path/to/file: {expires: ..., reason: ...}"
	// In YAML node structure: Content[0] = key node (path), Content[1] = value node (metadata map)
	if d.Kind == yaml.MappingNode {
		if len(d.Content) < 2 {
			return fmt.Errorf("invalid mapping node: expected at least 2 content nodes, got %d", len(d.Content))
		}

		// Extract path from key node
		keyNode := d.Content[0]
		if keyNode.Kind != yaml.ScalarNode {
			return fmt.Errorf("expected scalar node for path, got %v", keyNode.Kind)
		}
		path := keyNode.Value

		// Extract expires from value node (metadata map)
		var expiresStr string
		valueNode := d.Content[1]
		if valueNode.Kind == yaml.MappingNode {
			var metadata map[string]string
			if err := valueNode.Decode(&metadata); err != nil {
				return err
			}
			expiresStr = metadata["expires"]
		}

		*dse = newDotSnykExclude(path, expiresStr)
		return nil
	}

	return fmt.Errorf("unexpected yaml node kind: %v", d.Kind)
}

// parseExpireTime attempts to parse the expires string using multiple date formats
func parseExpireTime(expiresStr string) (time.Time, error) {
	if expiresStr == "" {
		return time.Time{}, nil
	}

	formats := []string{
		time.RFC3339,
		time.RFC1123Z,
		time.DateOnly,
		time.StampMilli,
	}

	var lastErr error
	for _, format := range formats {
		if t, err := time.Parse(format, expiresStr); err == nil {
			return t, nil
		} else {
			lastErr = err
		}
	}

	// Return error if all formats failed
	return time.Time{}, fmt.Errorf("failed to parse expires time '%s': %w", expiresStr, lastErr)
}

// parseIgnoreFile builds a list of glob patterns from a given .gitignore style file
func parseIgnoreFile(content []byte, filePath string) []string {
	var ignores []string
	lines := strings.Split(string(content), "\n")

	// Invalid .gitignore style patterns
	invalidRules := []string{"."}

	for _, line := range lines {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		globs := parseIgnoreRuleToGlobs(line, filePath, invalidRules)
		ignores = append(ignores, globs...)
	}
	return ignores
}

// escapeSpecialGlobChars escapes special characters that should be treated literally in glob patterns.
// Special Characters to escape: $
func escapeSpecialGlobChars(rule string) string {
	var result strings.Builder
	for i := 0; i < len(rule); i++ {
		ch := rule[i]
		switch ch {
		case '$':
			result.WriteByte('\\')
			result.WriteByte(ch)
		default:
			result.WriteByte(ch)
		}
	}
	return result.String()
}

// parseIgnoreRuleToGlobs contains the business logic to build glob patterns from a given ignore file
// we try to implement the same logic as gitignore pattern format - https://git-scm.com/docs/gitignore#_pattern_format
func parseIgnoreRuleToGlobs(rule string, filePath string, invalidRules []string) (globs []string) {
	// Mappings from .gitignore format to glob format:
	// `/foo/` => `/foo/**` (meaning: Ignore root (not sub) foo dir and its paths underneath.)
	// `/foo`	=> `/foo/**`, `/foo` (meaning: Ignore root (not sub) file and dir and its paths underneath.)
	// `foo/` => `**/foo/**` (meaning: Ignore (root/sub) foo dirs and their paths underneath.)
	// `foo` => `**/foo/**`, `foo` (meaning: Ignore (root/sub) foo filesToFilter and dirs and their paths underneath.)

	// If a rule is invalid, we skip it
	for _, invalidRule := range invalidRules {
		if strings.TrimSpace(rule) == invalidRule {
			return globs
		}
	}

	prefix := ""
	const negation = "!"
	const slash = "/"
	const all = "**"
	baseDir := filepath.ToSlash(filePath)

	if strings.HasPrefix(rule, negation) {
		rule = rule[1:]
		prefix = negation
	}

	// Special case: "/" pattern has no effect in gitignore
	if rule == slash {
		return globs
	}

	startingSlash := strings.HasPrefix(rule, slash)
	startingGlobstar := strings.HasPrefix(rule, all)
	endingSlash := strings.HasSuffix(rule, slash)
	endingGlobstar := strings.HasSuffix(rule, all)

	if startingSlash || startingGlobstar {
		// case `/foo/`, `/foo` => `{baseDir}/foo/**`
		// case `**/foo/`, `**/foo` => `{baseDir}/**/foo/**`
		if !endingGlobstar {
			glob := filepath.ToSlash(prefix + filepath.Join(baseDir, rule, all))
			globs = append(globs, escapeSpecialGlobChars(glob))
		}
		// case `/foo` => `{baseDir}/foo`
		// case `**/foo` => `{baseDir}/**/foo`
		// case `/foo/**` => `{baseDir}/foo/**`
		// case `**/foo/**` => `{baseDir}/**/foo/**`
		if !endingSlash {
			glob := filepath.ToSlash(prefix + filepath.Join(baseDir, rule))
			globs = append(globs, escapeSpecialGlobChars(glob))
		}
	} else {
		// case `foo/`, `foo` => `{baseDir}/**/foo/**`
		if !endingGlobstar {
			glob := filepath.ToSlash(prefix + filepath.Join(baseDir, all, rule, all))
			globs = append(globs, escapeSpecialGlobChars(glob))
		}
		// case `foo` => `{baseDir}/**/foo`
		// case `foo/**` => `{baseDir}/**/foo/**`
		if !endingSlash {
			glob := filepath.ToSlash(prefix + filepath.Join(baseDir, all, rule))
			globs = append(globs, escapeSpecialGlobChars(glob))
		}
	}
	return globs
}
