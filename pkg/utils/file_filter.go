package utils

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog"
	gitignore "github.com/sabhiram/go-gitignore"
	"golang.org/x/sync/semaphore"
	"gopkg.in/yaml.v3"
)

type FileFilter struct {
	path         string
	defaultRules []string
	cachedRuleSets []IgnoreRuleSet // populated by GetRules, consumed by GetFilteredFiles
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

// IgnoreRuleSet couples a compiled ignore matcher with the path it applies to. Rules are
// matched against paths relative to that path, so the base path is never embedded in a pattern.
type IgnoreRuleSet struct {
	path    string
	matcher *gitignore.GitIgnore
}

func newIgnoreRuleSet(path string, patterns ...string) IgnoreRuleSet {
	return IgnoreRuleSet{
		path:    path,
		matcher: gitignore.CompileIgnoreLines(patterns...),
	}
}

// getRuleSets is the internal implementation that builds per-directory rule sets.
func (fw *FileFilter) getRuleSets(ruleFiles []string) ([]IgnoreRuleSet, error) {
	var ignoreFiles []string
	for file := range fw.GetAllFiles() {
		if slices.Contains(ruleFiles, filepath.Base(file)) {
			ignoreFiles = append(ignoreFiles, file)
		}
	}

	ruleSets := []IgnoreRuleSet{newIgnoreRuleSet(fw.path, fw.defaultRules...)}

	for _, ignoreFile := range ignoreFiles {
		content, err := os.ReadFile(ignoreFile)
		if err != nil {
			return nil, err
		}

		var rules []string
		if filepath.Base(ignoreFile) == ".snyk" {
			rules = fw.parseDotSnykRules(content)
		} else {
			rules = parseGitIgnoreRules(content)
		}

		if len(rules) > 0 {
			ruleSets = append(ruleSets, newIgnoreRuleSet(filepath.Dir(ignoreFile), rules...))
		}
	}

	return ruleSets, nil
}

// TODO: change callers to use getRuleSets directly and pass []IgnoreRuleSet to GetFilteredFiles,
// then remove this backward-compatible wrapper.
func (fw *FileFilter) GetRules(ruleFiles []string) ([]string, error) {
	ruleSets, err := fw.getRuleSets(ruleFiles)
	if err != nil {
		return nil, err
	}
	fw.cachedRuleSets = ruleSets
	return fw.defaultRules, nil
}

// TODO: change signature to accept []IgnoreRuleSet from getRuleSets, then remove the globs parameter.
// GetFilteredFiles returns a channel of the filepaths that are not excluded by the ignore rules.
// The globs parameter is accepted for backward compatibility but ignored; rules come from the
// cachedRuleSets populated by the preceding GetRules call.
func (fw *FileFilter) GetFilteredFiles(filesCh chan string, globs []string) chan string {
	var filteredFilesCh = make(chan string)

	ruleSets := fw.cachedRuleSets
	if len(ruleSets) == 0 {
		ruleSets = []IgnoreRuleSet{newIgnoreRuleSet(fw.path, fw.defaultRules...)}
	}

	go func() {
		ctx := context.Background()
		availableThreads := semaphore.NewWeighted(fw.max_threads)

		defer close(filteredFilesCh)

		for file := range filesCh {
			err := availableThreads.Acquire(ctx, 1)
			if err != nil {
				fw.logger.Err(err).Msg("failed to limit threads")
			}
			go func(f string) {
				defer availableThreads.Release(1)
				if !isIgnored(f, ruleSets) {
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

// isIgnored reports whether f is excluded by any rule set whose path contains it.
func isIgnored(f string, ruleSets []IgnoreRuleSet) bool {
	for _, rs := range ruleSets {
		rel, err := filepath.Rel(rs.path, f)
		if err != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		if rel == ".." || strings.HasPrefix(rel, "../") {
			continue
		}
		if rs.matcher.MatchesPath(rel) {
			return true
		}
	}
	return false
}

// parseGitIgnoreRules returns the usable rules from a .gitignore/.dcignore file. go-gitignore
// handles comments, blank lines, negation and globbing itself; we only drop the bare "/" rule,
// which the library would otherwise treat as "match everything".
func parseGitIgnoreRules(content []byte) []string {
	var rules []string
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if strings.TrimPrefix(strings.TrimSpace(line), "!") == "/" {
			continue
		}
		rules = append(rules, line)
	}
	return rules
}

// parseDotSnykRules returns the exclude rules from a .snyk file as gitignore-style lines.
func (fw *FileFilter) parseDotSnykRules(content []byte) []string {
	type DotSnykRule struct {
		Exclude struct {
			Code   []dotSnykExclude `yaml:"code"`
			Global []dotSnykExclude `yaml:"global"`
		} `yaml:"exclude"`
	}

	var parsed DotSnykRule
	if err := yaml.Unmarshal(content, &parsed); err != nil {
		fw.logger.Error().Msgf("parse .snyk failed: %v", err)
		return nil
	}

	var rules []string
	for _, rule := range append(parsed.Exclude.Code, parsed.Exclude.Global...) {
		isExpired, err := rule.IsExpired()
		if err != nil {
			fw.logger.Error().Msgf("parse .snyk expires: %v", err)
		}
		if isExpired {
			continue
		}
		if filepath.IsAbs(rule.Path) {
			fw.logger.Warn().Msgf("Absolute paths are currently not supported when excluding files (%s)", rule.Path)
			continue
		}
		rules = append(rules, rule.Path)
	}
	return rules
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

// TODO: remove parseIgnoreRuleToGlobs — kept only because tests reference it directly.
// The function is no longer used by production code; the per-directory matching in getRuleSets
// delegates pattern handling entirely to go-gitignore.
func parseIgnoreRuleToGlobs(rule string, filePath string, invalidRules []string) (globs []string) {
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

	if rule == slash {
		return globs
	}

	startingSlash := strings.HasPrefix(rule, slash)
	startingGlobstar := strings.HasPrefix(rule, all)
	endingSlash := strings.HasSuffix(rule, slash)
	endingGlobstar := strings.HasSuffix(rule, all)

	buildGlob := func(prefix, baseDir string, parts ...string) string {
		return prefix + filepath.ToSlash(filepath.Join(append([]string{baseDir}, parts...)...))
	}

	if startingSlash || startingGlobstar {
		if !endingGlobstar {
			globs = append(globs, buildGlob(prefix, baseDir, rule, all))
		}
		if !endingSlash {
			globs = append(globs, buildGlob(prefix, baseDir, rule))
		}
	} else {
		if !endingGlobstar {
			globs = append(globs, buildGlob(prefix, baseDir, all, rule, all))
		}
		if !endingSlash {
			globs = append(globs, buildGlob(prefix, baseDir, all, rule))
		}
	}
	return globs
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
