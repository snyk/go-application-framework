package utils

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog"
	gitignore "github.com/sabhiram/go-gitignore"
	"golang.org/x/sync/semaphore"
	"gopkg.in/yaml.v3"
)

type SourcedRules struct {
	Gitignore []string // globs derived only from .gitignore files
	Other     []string // globs from .snyk, .dcignore, and FileFilter's default rules
}

// matchersBySource is SourcedRules compiled into matchers, one per source.
type matchersBySource struct {
	Other     *gitignore.GitIgnore
	Gitignore *gitignore.GitIgnore
}

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
	ignoreFiles := fw.findIgnoreFiles(ruleFiles)
	globs, err := fw.buildGlobs(ignoreFiles)
	if err != nil {
		return nil, err
	}

	return append(fw.defaultRules, globs...), nil
}

// GetRulesBySource is like GetRules, but keeps .gitignore-sourced globs separate from every
// other source instead of merging everything into one flat list.
func (fw *FileFilter) GetRulesBySource(ruleFiles []string) (SourcedRules, error) {
	ignoreFiles := fw.findIgnoreFiles(ruleFiles)
	rules, err := fw.buildSourcedRules(ignoreFiles)
	return rules, err
}

// findIgnoreFiles walks fw.path and returns every file whose name matches one of ruleFiles.
func (fw *FileFilter) findIgnoreFiles(ruleFiles []string) []string {
	files := fw.GetAllFiles()

	var ignoreFiles = make([]string, 0)
	for file := range files {
		fileName := filepath.Base(file)
		for _, ruleFile := range ruleFiles {
			if fileName == ruleFile {
				ignoreFiles = append(ignoreFiles, file)
			}
		}
	}

	return ignoreFiles
}

// buildSourcedRules is like buildGlobs, but keeps .gitignore-sourced globs separate from every
// other source (see SourcedRules).
func (fw *FileFilter) buildSourcedRules(ignoreFiles []string) (SourcedRules, error) {
	rules := SourcedRules{Other: append([]string{}, fw.defaultRules...)}
	for _, ignoreFile := range ignoreFiles {
		content, err := os.ReadFile(ignoreFile)
		if err != nil {
			return SourcedRules{}, err
		}

		dir := filepath.Dir(ignoreFile)
		switch filepath.Base(ignoreFile) {
		case ".snyk":
			rules.Other = append(rules.Other, fw.parseDotSnykFile(content, dir)...)
		case ".gitignore":
			rules.Gitignore = append(rules.Gitignore, parseIgnoreFile(content, dir)...)
		default:
			rules.Other = append(rules.Other, parseIgnoreFile(content, dir)...)
		}
	}

	return rules, nil
}

// GetFilteredFiles returns a filtered channel of filepaths from a given channel of filespaths and glob patterns to filter on
func (fw *FileFilter) GetFilteredFiles(filesCh chan string, globs []string) chan string {
	matcher := gitignore.CompileIgnoreLines(globs...)
	shouldKeepFn := func(filePath string) bool {
		return !matcher.MatchesPath(filePath)
	}
	return fw.filterFiles(filesCh, shouldKeepFn)
}

// GetFilteredFilesBySource is like GetFilteredFiles, but rules.Other always excludes while
// rules.Gitignore excludes only untracked files (CLI-1411: git only ignores untracked files).
func (fw *FileFilter) GetFilteredFilesBySource(filesCh chan string, rules SourcedRules) chan string {
	filter := fw.NewFilterBySource(rules)
	return fw.filterFiles(filesCh, filter.ShouldKeep)
}

// shouldKeepBySource: matchers.Other always excludes; matchers.Gitignore excludes unless
// filePath is a tracked match (nil trackedGitignoreMatches means fail-open: exclude as usual).
// filePath is a path as produced by GetAllFiles (rooted at scanRoot; not necessarily absolute).
func shouldKeepBySource(filePath string, scanRoot string, matchers matchersBySource, trackedGitignoreMatches map[string]bool) bool {
	if matchers.Other.MatchesPath(filePath) {
		return false
	}

	matchesGitignore := matchers.Gitignore.MatchesPath(filePath)
	if !matchesGitignore {
		return true
	}

	return isTrackedMatch(filePath, scanRoot, trackedGitignoreMatches)
}

// isTrackedMatch reports whether filePath (relative to scanRoot) is a key in
// trackedGitignoreMatches; false if trackedGitignoreMatches is nil (no git repo) or filePath
// can't be made relative to scanRoot.
func isTrackedMatch(filePath string, scanRoot string, trackedGitignoreMatches map[string]bool) bool {
	if trackedGitignoreMatches == nil {
		return false
	}
	rel, err := filepath.Rel(scanRoot, filePath)
	if err != nil {
		return false
	}
	return trackedGitignoreMatches[filepath.ToSlash(rel)]
}

// filterFiles reads filesCh, keeping only files for which shouldKeepFn returns true.
func (fw *FileFilter) filterFiles(filesCh chan string, shouldKeepFn func(string) bool) chan string {
	var filteredFilesCh = make(chan string)

	go func() {
		ctx := context.Background()
		availableThreads := semaphore.NewWeighted(fw.max_threads)

		defer close(filteredFilesCh)

		// iterate the filesToFilter channel
		for filePath := range filesCh {
			err := availableThreads.Acquire(ctx, 1)
			if err != nil {
				fw.logger.Err(err).Msg("failed to limit threads")
			}
			go func(filePath string) {
				defer availableThreads.Release(1)
				if shouldKeepFn(filePath) {
					filteredFilesCh <- filePath
				}
			}(filePath)
		}

		// wait until the last thread is done
		err := availableThreads.Acquire(ctx, fw.max_threads)
		if err != nil {
			fw.logger.Err(err).Msg("failed to wait for all threads")
		}
	}()

	return filteredFilesCh
}

// trackedFilesMatching returns tracked files (relative to fw.path) that match gitignoreMatcher,
// bounding memory to that intersection. Returns nil if fw.path isn't a git repo (fail-open).
func (fw *FileFilter) trackedFilesMatching(gitignoreMatcher *gitignore.GitIgnore) map[string]bool {
	start := time.Now()

	absScanRoot, err := filepath.Abs(fw.path)
	if err != nil {
		fw.logger.Warn().Err(err).Msg("could not resolve absolute scan path to check for tracked files; " +
			"gitignore-matched files will be excluded as usual")
		return nil
	}

	repo, err := git.PlainOpenWithOptions(absScanRoot, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		if errors.Is(err, git.ErrRepositoryNotExists) {
			fw.logger.Debug().Msg("not a git repository; gitignore-matched files will be excluded as usual")
			return nil
		}
		fw.logger.Warn().Err(err).Msg("could not open git repository to check for tracked files; " +
			"gitignore-matched files will be excluded as usual")
		return nil
	}

	worktree, err := repo.Worktree()
	if err != nil {
		fw.logger.Warn().Err(err).Msg("could not read git worktree to check for tracked files")
		return nil
	}

	idx, err := repo.Storer.Index()
	if err != nil {
		fw.logger.Warn().Err(err).Msg("could not read git index to check for tracked files")
		return nil
	}

	repoRoot := worktree.Filesystem.Root()

	// go-git resolves symlinks in the repo root (e.g. macOS's /var -> /private/var); match that
	// so a symlinked scan root doesn't make every entry look outside the scan root.
	scanRootForCompare := absScanRoot
	if resolved, err := filepath.EvalSymlinks(absScanRoot); err == nil {
		scanRootForCompare = resolved
	}

	trackedNames := make([]string, len(idx.Entries))
	for i, entry := range idx.Entries {
		trackedNames[i] = entry.Name
	}

	tracked := matchTrackedEntries(trackedNames, repoRoot, scanRootForCompare, fw.path, gitignoreMatcher)
	trackedFileNames := SortedMapKeys(tracked)

	fw.logger.Debug().
		Int("trackedGitignoreMatches", len(tracked)).
		Strs("trackedGitignoreFiles", trackedFileNames).
		Dur("duration", time.Since(start)).
		Msg("checked git index for tracked files matching .gitignore rules")

	if len(trackedFileNames) > 0 {
		fw.logger.Warn().
			Strs("trackedGitignoreFiles", trackedFileNames).
			Msg("some git-tracked files match a .gitignore rule and will still be scanned")
	}

	return tracked
}

// matchTrackedEntries returns, out of trackedNames (repo-root-relative paths from a git index),
// those that fall under scanRoot and match gitignoreMatcher — keyed by path relative to fwPath,
// the same shape GetAllFiles produces.
func matchTrackedEntries(trackedNames []string, repoRoot, scanRoot, fwPath string, gitignoreMatcher *gitignore.GitIgnore) map[string]bool {
	tracked := make(map[string]bool)
	for _, name := range trackedNames {
		entryAbsPath := filepath.Join(repoRoot, filepath.FromSlash(name))

		relToScanRoot, err := filepath.Rel(scanRoot, entryAbsPath)
		if err != nil || strings.HasPrefix(relToScanRoot, "..") {
			continue // outside the directory being scanned
		}
		relSlash := filepath.ToSlash(relToScanRoot)

		// re-anchor to fwPath so this matches the path shape GetAllFiles produces.
		candidatePath := filepath.Join(fwPath, filepath.FromSlash(relSlash))
		if gitignoreMatcher.MatchesPath(candidatePath) {
			tracked[relSlash] = true
		}
	}
	return tracked
}

// buildGlobs iterates a list of ignore filesToFilter and returns a list of glob patterns that can be used to test for ignored filesToFilter
func (fw *FileFilter) buildGlobs(ignoreFiles []string) ([]string, error) {
	var globs = make([]string, 0)
	for _, ignoreFile := range ignoreFiles {
		var content []byte
		content, err := os.ReadFile(ignoreFile)
		if err != nil {
			return nil, err
		}

		if filepath.Base(ignoreFile) == ".snyk" { // .snyk files are yaml files and should be parsed differently
			parsedRules := fw.parseDotSnykFile(content, filepath.Dir(ignoreFile))
			globs = append(globs, parsedRules...)
		} else { // .gitignore, .dcignore, etc. are just a list of ignore rules
			parsedRules := parseIgnoreFile(content, filepath.Dir(ignoreFile))
			globs = append(globs, parsedRules...)
		}
	}

	return globs, nil
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

// ruleRegexMetaChars are regex metacharacters that gitignore treats as literal, so they must be
// escaped before the rule reaches the regex-based go-gitignore matcher (e.g. a folder literally
// named "build (old)"). Glob syntax the matcher relies on is deliberately excluded: "*", "?",
// "[", "]" (wildcards / character classes) and "^" (character-class negation, e.g. "cache[^S]").
var ruleRegexMetaChars = map[byte]bool{
	'$': true,
	'(': true,
	')': true,
	'+': true,
	'|': true,
	'{': true,
	'}': true,
}

// escapeSpecialGlobChars escapes regex metacharacters in an ignore rule that gitignore treats as
// literal, so they match literally instead of being interpreted by go-gitignore's regex engine.
func escapeSpecialGlobChars(rule string) string {
	var result strings.Builder
	for i := 0; i < len(rule); i++ {
		ch := rule[i]
		if ruleRegexMetaChars[ch] {
			result.WriteByte('\\')
		}
		result.WriteByte(ch)
	}
	return result.String()
}

// joinGlob joins path parts like path.Join but preserves a leading "//" (UNC path prefix).
// path.Clean (called by path.Join) collapses "//" to "/", which breaks UNC paths on Windows.
func joinGlob(parts ...string) string {
	result := path.Join(parts...)
	if len(parts) > 0 && strings.HasPrefix(parts[0], "//") && !strings.HasPrefix(result, "//") {
		result = "/" + result
	}
	return result
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
	baseDir = regexp.QuoteMeta(baseDir)
	// Undo escaping for chars that go-gitignore already escapes internally,
	// otherwise they get double-escaped and fail to match literal paths.
	baseDir = strings.ReplaceAll(baseDir, `\.`, ".")
	baseDir = strings.ReplaceAll(baseDir, `\?`, "?")

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
			glob := prefix + joinGlob(baseDir, escapeSpecialGlobChars(rule), all)
			globs = append(globs, glob)
		}
		// case `/foo` => `{baseDir}/foo`
		// case `**/foo` => `{baseDir}/**/foo`
		// case `/foo/**` => `{baseDir}/foo/**`
		// case `**/foo/**` => `{baseDir}/**/foo/**`
		if !endingSlash {
			glob := prefix + joinGlob(baseDir, escapeSpecialGlobChars(rule))
			globs = append(globs, glob)
		}
	} else {
		// case `foo/`, `foo` => `{baseDir}/**/foo/**`
		if !endingGlobstar {
			glob := prefix + joinGlob(baseDir, all, escapeSpecialGlobChars(rule), all)
			globs = append(globs, glob)
		}
		// case `foo` => `{baseDir}/**/foo`
		// case `foo/**` => `{baseDir}/**/foo/**`
		if !endingSlash {
			glob := prefix + joinGlob(baseDir, all, escapeSpecialGlobChars(rule))
			globs = append(globs, glob)
		}
	}
	return globs
}

// FilterBySource is a reusable, precompiled by-source filter: matchers and a git-tracked-files
// snapshot are built once, so ShouldKeep can be called cheaply many times afterward (no I/O per
// call). Use this instead of GetFilteredFilesBySource when you evaluate paths one at a time over
// a long lifetime — e.g. a file watcher reacting to individual events — rather than draining a
// batch channel; calling GetFilteredFilesBySource per path would re-read the git index every time.
type FilterBySource struct {
	scanRoot                string
	matchers                matchersBySource
	trackedGitignoreMatches map[string]bool
}

// NewFilterBySource builds a FilterBySource from rules, reading the git index once. Rebuild it
// whenever rules changes (e.g. on the same cadence you'd already rebuild your own ignore matcher).
func (fw *FileFilter) NewFilterBySource(rules SourcedRules) *FilterBySource {
	matchers := matchersBySource{
		Other:     gitignore.CompileIgnoreLines(rules.Other...),
		Gitignore: gitignore.CompileIgnoreLines(rules.Gitignore...),
	}
	return &FilterBySource{
		scanRoot:                fw.path,
		matchers:                matchers,
		trackedGitignoreMatches: fw.trackedFilesMatching(matchers.Gitignore),
	}
}

// ShouldKeep reports whether filePath should be kept (not excluded), using this FilterBySource's
// precompiled matchers and tracked-files snapshot. Does no I/O — safe to call per event.
func (f *FilterBySource) ShouldKeep(filePath string) bool {
	return shouldKeepBySource(filePath, f.scanRoot, f.matchers, f.trackedGitignoreMatches)
}
