package utils

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog"
	gitignore "github.com/sabhiram/go-gitignore"
	"golang.org/x/sync/semaphore"
	"gopkg.in/yaml.v3"

	"github.com/snyk/go-application-framework/internal/metrics"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

const (
	FF_FILE_FILTER_METACHARACTER_FIX   string = "internal_snyk_file_filter_metacharacter_fix_enabled"   // FF_FILE_FILTER_METACHARACTER_FIX (boolean) enables the fix for ignore rules and paths containing regex metacharacters
	FF_GITIGNORE_RESPECT_TRACKED_FILES string = "internal_snyk_gitignore_respect_tracked_files_enabled" // FF_GITIGNORE_RESPECT_TRACKED_FILES (boolean) enables tracked-file-aware .gitignore filtering (CLI-1411)
)

// by default, all rules are valid
var defaultInvalidRules = []string{}

const gitIgnoreGlobPrefix = "#gitignore:"

type FileFilter struct {
	path            string
	defaultRules    []string
	logger          *zerolog.Logger
	max_threads     int64
	dotSnykSections []DotSnykExcludeSectionName
	config          configuration.Configuration
	metrics         *metrics.Accumulator
}

// DotSnykExcludeSectionName is the name of an `exclude` section in a .snyk
// file (e.g. "code", "global", "secrets", "iac-drift"). It is a plain string so callers can
// opt into sections this package doesn't define constants for without requiring
// a code change here.
type DotSnykExcludeSectionName string

const (
	DotSnykExcludeGlobal   DotSnykExcludeSectionName = "global"
	DotSnykExcludeCode     DotSnykExcludeSectionName = "code"
	DotSnykExcludeSecrets  DotSnykExcludeSectionName = "secrets"
	DotSnykExcludeIacDrift DotSnykExcludeSectionName = "iac-drift"
)

// String implements fmt.Stringer.
func (s DotSnykExcludeSectionName) String() string {
	return string(s)
}

// DotSnykRule mirrors the relevant parts of a .snyk policy file.
// Exclude keys its sections by name (e.g. "code", "global") so new sections are picked up by
// decoding alone, without changes to this type.
// Only the sections a caller opts into are decoded into rules.
// A malformed section a caller does not request is ignored.
// A malformed section requested section is skipped.
type DotSnykRule struct {
	Exclude map[DotSnykExcludeSectionName]yaml.Node `yaml:"exclude"`
}

// File-filter metric keys have the shape "file-filter.<variant>.<metric>".
const (
	metricFileFilterPrefix = "file-filter" // prefix for all file-filter analytics keys

	metricFileFilterVariantLegacy       = "var0" // neither feature flag enabled
	metricFileFilterVariantMetacharFix  = "var1" // FF_FILE_FILTER_METACHARACTER_FIX only
	metricFileFilterVariantTrackedFiles = "var2" // FF_GITIGNORE_RESPECT_TRACKED_FILES only
	metricFileFilterVariantBothFixes    = "var3" // both feature flags enabled

	metricFileFilterInputFileCount = "filter.inputFileCount" // files offered to GetFilteredFiles, before exclusion
	metricFileFilterRuleCount      = "filter.ruleCount"      // glob patterns GetRules produced

	// Record feature flags alongside the variant so consumers need not decode its name.
	metricFileFilterFeatureMetacharFix  = "feature.metaCharFix"    // whether FF_FILE_FILTER_METACHARACTER_FIX applied to the run
	metricFileFilterFeatureTrackedFiles = "feature.includeTracked" // whether FF_GITIGNORE_RESPECT_TRACKED_FILES applied to the run

	metricFileFilterDurationMs           = "filter.durationMs"      // elapsed time for GetFilteredFiles, including the caller's drain of the result channel
	metricFileFilterRulesBuildDurationMs = "rules.durationMs"       // elapsed time for GetRules: directory walk, ignore discovery, and buildGlobs
	metricFileFilterSurvivingFileCount   = "filter.outputFileCount" // number of files that passed exclusion
)

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

// WithDotSnykSections sets which .snyk exclude sections
// (e.g. DotSnykExcludeCode, DotSnykExcludeGlobal, DotSnykExcludeSecrets, DotSnykExcludeIacDrift)
// the FileFilter applies. It replaces the FileFilter's default
// sections of DotSnykExcludeCode and DotSnykExcludeGlobal rather than adding to them. Passing an empty
// slice disables all .snyk-based exclusions.
func WithDotSnykSections(sections []DotSnykExcludeSectionName) FileFilterOption {
	return func(filter *FileFilter) error {
		filter.dotSnykSections = sections
		return nil
	}
}

// WithConfig supplies the loaded configuration; feature flag values are read when the option is applied;
// if config is nil the default config will be applied
func WithConfig(config configuration.Configuration) FileFilterOption {
	return func(filter *FileFilter) error {
		if config == nil {
			filter.config = configuration.NewWithOpts()
			return nil
		}
		filter.config = config
		return nil
	}
}

// WithMetrics supplies a recorder for aggregated file-filter analytics.
func WithMetrics(recorder metrics.Recorder) FileFilterOption {
	return func(filter *FileFilter) error {
		filter.metrics = metrics.NewAccumulator(recorder)
		return nil
	}
}

// Avoid computing metrics when no recorder is configured.
func (fw *FileFilter) recordSumLazy(variant, key string, getMetric func() int) {
	if fw.metrics.IsRecording() {
		fw.metrics.AddToSum(metricKey(variant, key), getMetric())
	}
}

// Avoid resolving flags, which may require network access, when metrics are disabled.
func (fw *FileFilter) metricVariant() string {
	if !fw.metrics.IsRecording() {
		return ""
	}

	metacharacterFix := fw.config.GetBool(FF_FILE_FILTER_METACHARACTER_FIX)
	respectTrackedFiles := fw.config.GetBool(FF_GITIGNORE_RESPECT_TRACKED_FILES)

	var variant string
	switch {
	case metacharacterFix && respectTrackedFiles:
		variant = metricFileFilterVariantBothFixes
	case metacharacterFix:
		variant = metricFileFilterVariantMetacharFix
	case respectTrackedFiles:
		variant = metricFileFilterVariantTrackedFiles
	default:
		variant = metricFileFilterVariantLegacy
	}

	fw.metrics.RecordBool(metricKey(variant, metricFileFilterFeatureMetacharFix), metacharacterFix)
	fw.metrics.RecordBool(metricKey(variant, metricFileFilterFeatureTrackedFiles), respectTrackedFiles)

	return variant
}

func metricKey(variant, key string) string {
	return fmt.Sprintf("%s.%s.%s", metricFileFilterPrefix, variant, key)
}

// NewFileFilter creates a FileFilter rooted at path. Without WithConfig, feature flags default to disabled (legacy).
func NewFileFilter(path string, logger *zerolog.Logger, options ...FileFilterOption) *FileFilter {
	filter := &FileFilter{
		path:            path,
		defaultRules:    []string{"**/.git/**"},
		logger:          logger,
		max_threads:     int64(runtime.NumCPU()),
		dotSnykSections: []DotSnykExcludeSectionName{DotSnykExcludeCode, DotSnykExcludeGlobal}, // init default with DotSnykExcludeCode and DotSnykExcludeGlobal to keep it backwards compatible
		metrics:         metrics.NewAccumulator(nil),
	}

	options = append([]FileFilterOption{WithConfig(nil)}, options...)

	for _, option := range options {
		err := option(filter)
		if err != nil {
			logger.Err(err).Msg("failed to apply option for FileFilter")
		}
	}

	return filter
}

func NewFileFilterFromConfig(path string, logger *zerolog.Logger, config configuration.Configuration, options ...FileFilterOption) *FileFilter {
	allOptions := append([]FileFilterOption{WithConfig(config)}, options...)
	return NewFileFilter(path, logger, allOptions...)
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
	// Rule building and filtering may resolve feature flags at different times.
	variant := fw.metricVariant()
	start := time.Now()
	defer fw.recordSumLazy(variant, metricFileFilterRulesBuildDurationMs, func() int {
		return int(time.Since(start).Milliseconds())
	})
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

	rules := append(fw.defaultRules, globs...)

	recordRulesCount := func() int { return len(rules) }
	fw.recordSumLazy(variant, metricFileFilterRuleCount, recordRulesCount)

	return rules, nil
}

// GetFilteredFiles returns a filtered channel of filepaths from a given channel of filespaths and glob patterns to filter on
func (fw *FileFilter) GetFilteredFiles(filesCh chan string, globs []string) chan string {
	var filteredFilesCh = make(chan string)

	go func() {
		ctx := context.Background()
		availableThreads := semaphore.NewWeighted(fw.max_threads)
		variant := fw.metricVariant()
		start := time.Now()
		var resolvedFileCount atomic.Int64
		candidateFileCount := 0

		defer close(filteredFilesCh)

		// Building the predicate is part of the run: with FF_GITIGNORE_RESPECT_TRACKED_FILES it
		// opens the repository and reads the git index, so it is timed alongside the filtering.
		var isFileExcluded func(string) bool
		if fw.config.GetBool(FF_GITIGNORE_RESPECT_TRACKED_FILES) {
			isFileExcluded = fw.trackedFileExclusionPredicate(globs)
		} else {
			globPatternMatcher := gitignore.CompileIgnoreLines(globs...)
			isFileExcluded = func(filePath string) bool {
				return globPatternMatcher.MatchesPath(filePath)
			}
		}

		// iterate the filesToFilter channel
		for file := range filesCh {
			candidateFileCount++
			err := availableThreads.Acquire(ctx, 1)
			if err != nil {
				fw.logger.Err(err).Msg("failed to limit threads")
			}
			go func(f string) {
				defer availableThreads.Release(1)
				// filesToFilter that do not match the glob pattern are filtered
				if !isFileExcluded(f) {
					filteredFilesCh <- f
					resolvedFileCount.Add(1)
				}
			}(file)
		}

		// wait until the last thread is done
		err := availableThreads.Acquire(ctx, fw.max_threads)
		if err != nil {
			fw.logger.Err(err).Msg("failed to wait for all threads")
		}

		fw.recordSumLazy(variant, metricFileFilterInputFileCount, func() int {
			return candidateFileCount
		})
		fw.recordSumLazy(variant, metricFileFilterSurvivingFileCount, func() int {
			return int(resolvedFileCount.Load())
		})

		fw.recordSumLazy(variant, metricFileFilterDurationMs, func() int { return int(time.Since(start).Milliseconds()) })
	}()

	return filteredFilesCh
}

// buildGlobs iterates a list of ignore filesToFilter and returns a list of glob patterns that can be used to test for ignored filesToFilter
func (fw *FileFilter) buildGlobs(ignoreFiles []string) ([]string, error) {
	if len(ignoreFiles) == 0 {
		return nil, nil
	}

	enableMetacharacterFix := fw.config.GetBool(FF_FILE_FILTER_METACHARACTER_FIX)
	respectGitIgnoreTrackedFiles := fw.config.GetBool(FF_GITIGNORE_RESPECT_TRACKED_FILES)

	var globs = make([]string, 0)
	for _, ignoreFile := range ignoreFiles {
		var content []byte
		content, err := os.ReadFile(ignoreFile)
		if err != nil {
			return nil, err
		}

		if filepath.Base(ignoreFile) == ".snyk" { // .snyk files are yaml files and should be parsed differently
			parsedRules := fw.parseDotSnykFile(content, filepath.Dir(ignoreFile), enableMetacharacterFix)
			globs = append(globs, parsedRules...)
		} else { // .gitignore, .dcignore, etc. are just a list of ignore rules
			parsedRules := parseIgnoreFile(content, filepath.Dir(ignoreFile), enableMetacharacterFix)
			if filepath.Base(ignoreFile) == ".gitignore" && respectGitIgnoreTrackedFiles {
				for i, rule := range parsedRules {
					parsedRules[i] = gitIgnoreGlobPrefix + rule
				}
			}
			globs = append(globs, parsedRules...)
		}
	}

	return globs, nil
}

// trackedFileExclusionPredicate builds the exclusion predicate used when
// FF_GITIGNORE_RESPECT_TRACKED_FILES is enabled. keptCount is incremented for every file that a
// .gitignore rule would have excluded but that is kept because git tracks it, i.e. it is
// exempted from the .gitignore rule and not excluded by any other rule (e.g. a .snyk or
// .dcignore rule).
func (fw *FileFilter) trackedFileExclusionPredicate(globs []string) func(string) bool {
	allGlobs := make([]string, 0, len(globs))
	hasGitignoreGlobs := false

	for _, glob := range globs {
		if gitignoreGlob, ok := strings.CutPrefix(glob, gitIgnoreGlobPrefix); ok {
			allGlobs = append(allGlobs, gitignoreGlob)
			hasGitignoreGlobs = true
			continue
		}

		allGlobs = append(allGlobs, glob)
	}

	otherMatcher := gitignore.CompileIgnoreLines(globs...)

	allMatcher := gitignore.CompileIgnoreLines(allGlobs...)
	defaultPredicate := func(file string) bool {
		return allMatcher.MatchesPath(filepath.ToSlash(file))
	}

	if !hasGitignoreGlobs {
		return defaultPredicate
	}

	repo, err := git.PlainOpenWithOptions(fw.path, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		fw.logger.Debug().Msgf("failed to open git repository: %v", err)
		return defaultPredicate
	}

	worktree, err := repo.Worktree()
	if err != nil {
		fw.logger.Debug().Msgf("failed to get worktree: %v", err)
		return defaultPredicate
	}

	gitIndex, err := repo.Storer.Index()
	if err != nil {
		fw.logger.Debug().Msgf("failed to get git index: %v", err)
		return defaultPredicate
	}

	repoRoot, err := matchingRepositoryRoot(fw.path, worktree.Filesystem.Root())
	if err != nil {
		fw.logger.Debug().Msgf("failed to resolve git repository root: %v", err)
		return defaultPredicate
	}

	trackedFiles := make(map[string]bool, len(gitIndex.Entries))
	for _, entry := range gitIndex.Entries {
		trackedFiles[entry.Name] = true
	}

	return func(file string) bool {
		normalizedPath := filepath.ToSlash(file)
		relativePath, err := filepath.Rel(repoRoot, file)
		if err != nil {
			return allMatcher.MatchesPath(normalizedPath)
		}

		if trackedFiles[filepath.ToSlash(relativePath)] {
			return otherMatcher.MatchesPath(normalizedPath)
		}

		return allMatcher.MatchesPath(normalizedPath)
	}
}

func matchingRepositoryRoot(scanRoot, worktreeRoot string) (string, error) {
	absoluteScanRoot, err := filepath.Abs(scanRoot)
	if err != nil {
		return "", err
	}

	resolvedScanRoot, err := filepath.EvalSymlinks(absoluteScanRoot)
	if err != nil {
		return "", err
	}

	resolvedWorktreeRoot, err := filepath.EvalSymlinks(worktreeRoot)
	if err != nil {
		return "", err
	}

	relativeRoot, err := filepath.Rel(resolvedScanRoot, resolvedWorktreeRoot)
	if err != nil {
		return "", err
	}

	return filepath.Clean(filepath.Join(scanRoot, relativeRoot)), nil
}

// parseDotSnykFile builds a list of glob patterns from a given .snyk style file
func (fw *FileFilter) parseDotSnykFile(content []byte, filePath string, enableMetacharacterFix bool) []string {
	var rules DotSnykRule
	err := yaml.Unmarshal(content, &rules)
	if err != nil {
		fw.logger.Error().Msgf("parse .snyk failed: %v", err)
		return nil
	}

	// collect rules according to fw.dotSnykSections, decoding each requested
	// section independently so a malformed section we don't care about (or a
	// malformed sibling of one we do) cannot drop the sections we do apply.
	var allRules []dotSnykExclude
	for _, section := range fw.dotSnykSections {
		node, ok := rules.Exclude[section]
		if !ok {
			continue
		}

		var sectionRules []dotSnykExclude
		if err := node.Decode(&sectionRules); err != nil {
			fw.logger.Error().Msgf("parse .snyk section %q failed: %v", section, err)
			continue
		}

		allRules = append(allRules, sectionRules...)
	}

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

		globs = append(globs, parseIgnoreRuleToGlobs(rule.Path, filePath, defaultInvalidRules, enableMetacharacterFix)...)
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

// parseIgnoreFile builds a list of glob patterns from a given .gitignore style file.
func parseIgnoreFile(content []byte, filePath string, enableMetacharacterFix bool) []string {
	var ignores []string
	lines := strings.Split(string(content), "\n")

	// Invalid .gitignore style patterns
	invalidRules := []string{"."}

	for _, line := range lines {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		globs := parseIgnoreRuleToGlobs(line, filePath, invalidRules, enableMetacharacterFix)
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

// escapeIgnoreRuleMetaChars escapes regex metacharacters in an ignore rule that gitignore treats
// as literal, so they match literally instead of being interpreted by go-gitignore's regex
// engine. This is the fixed behavior, gated behind FF_FILE_FILTER_METACHARACTER_FIX.
func escapeIgnoreRuleMetaChars(rule string) string {
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

// escapeSpecialGlobCharsLegacy escapes special characters that should be treated literally in
// glob patterns. Special Characters to escape: $
// This is the legacy behavior, to be removed in future releases.
func escapeSpecialGlobCharsLegacy(rule string) string {
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
func parseIgnoreRuleToGlobs(rule string, filePath string, invalidRules []string, enableMetacharacterFix bool) (globs []string) {
	// Mappings from .gitignore format to glob format:
	// `/foo/` => `/foo/**` (meaning: Ignore root (not sub) foo dir and its paths underneath.)
	// `/foo`	=> `/foo/**`, `/foo` (meaning: Ignore root (not sub) file and dir and its paths underneath.)
	// `foo/` => `**/foo/**` (meaning: Ignore (root/sub) foo dirs and their paths underneath.)
	// `foo` => `**/foo/**`, `foo` (meaning: Ignore (root/sub) foo filesToFilter and dirs and their paths underneath.)

	// If a rule is invalid, we skip it
	if slices.Contains(invalidRules, strings.TrimSpace(rule)) {
		return globs
	}

	if !enableMetacharacterFix {
		return parseIgnoreRuleToGlobsLegacy(rule, filePath)
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
			glob := prefix + joinGlob(baseDir, escapeIgnoreRuleMetaChars(rule), all)
			globs = append(globs, glob)
		}
		// case `/foo` => `{baseDir}/foo`
		// case `**/foo` => `{baseDir}/**/foo`
		// case `/foo/**` => `{baseDir}/foo/**`
		// case `**/foo/**` => `{baseDir}/**/foo/**`
		if !endingSlash {
			glob := prefix + joinGlob(baseDir, escapeIgnoreRuleMetaChars(rule))
			globs = append(globs, glob)
		}
	} else {
		// case `foo/`, `foo` => `{baseDir}/**/foo/**`
		if !endingGlobstar {
			glob := prefix + joinGlob(baseDir, all, escapeIgnoreRuleMetaChars(rule), all)
			globs = append(globs, glob)
		}
		// case `foo` => `{baseDir}/**/foo`
		// case `foo/**` => `{baseDir}/**/foo/**`
		if !endingSlash {
			glob := prefix + joinGlob(baseDir, all, escapeIgnoreRuleMetaChars(rule))
			globs = append(globs, glob)
		}
	}
	return globs
}

// parseIgnoreRuleToGlobsLegacy to be removed in future releases.
func parseIgnoreRuleToGlobsLegacy(rule string, filePath string) (globs []string) {
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
			globs = append(globs, escapeSpecialGlobCharsLegacy(glob))
		}
		// case `/foo` => `{baseDir}/foo`
		// case `**/foo` => `{baseDir}/**/foo`
		// case `/foo/**` => `{baseDir}/foo/**`
		// case `**/foo/**` => `{baseDir}/**/foo/**`
		if !endingSlash {
			glob := filepath.ToSlash(prefix + filepath.Join(baseDir, rule))
			globs = append(globs, escapeSpecialGlobCharsLegacy(glob))
		}
	} else {
		// case `foo/`, `foo` => `{baseDir}/**/foo/**`
		if !endingGlobstar {
			glob := filepath.ToSlash(prefix + filepath.Join(baseDir, all, rule, all))
			globs = append(globs, escapeSpecialGlobCharsLegacy(glob))
		}
		// case `foo` => `{baseDir}/**/foo`
		// case `foo/**` => `{baseDir}/**/foo/**`
		if !endingSlash {
			glob := filepath.ToSlash(prefix + filepath.Join(baseDir, all, rule))
			globs = append(globs, escapeSpecialGlobCharsLegacy(glob))
		}
	}
	return globs
}
