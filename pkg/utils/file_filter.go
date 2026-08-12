package utils

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
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

var nextFileFilterMetricScopeID atomic.Uint64

const gitIgnoreGlobPrefix = "#gitignore:"

type FileFilter struct {
	path            string
	defaultRules    []string
	logger          *zerolog.Logger
	max_threads     int64
	dotSnykSections []DotSnykExcludeSectionName
	config          configuration.Configuration
	metricsRecorder metrics.Recorder
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

const (
	metricFileFilterPrefix = "file-filter" // prefix for all file-filter analytics keys

	metricFileFilterDurationMs            = "durationMs"            // elapsed time for GetFilteredFiles: exclusion-predicate build (incl. git index read) and filtering, including caller drain of the result channel
	metricFileFilterSurvivingFileCount    = "survivingFileCount"    // number of files that passed exclusion in this filter run
	metricFileFilterRulesBuildDurationMs  = "rulesBuildDurationMs"  // elapsed time for GetRules: directory walk, ignore discovery, and buildGlobs
	metricFileFilterMetacharacterFix      = "metacharacterFix"      // whether FF_FILE_FILTER_METACHARACTER_FIX was enabled for this run
	metricFileFilterRespectTrackedFiles   = "respectTrackedFiles"   // whether FF_GITIGNORE_RESPECT_TRACKED_FILES was enabled for this run
	metricFileFilterTrackedFilesKeptCount = "trackedFilesKeptCount" // tracked files kept despite a matching .gitignore rule
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

// WithMetrics supplies a recorder for file-filter analytics values.
// Callers must pass a pkg/analytics.Analytics implementation here; it satisfies this interface.
func WithMetrics(recorder metrics.Recorder) FileFilterOption {
	return func(filter *FileFilter) error {
		filter.metricsRecorder = recorder
		return nil
	}
}

func (fw *FileFilter) recordMetricLazy(scopeID, key string, getMetric func() int) {
	if fw.metricsRecorder != nil {
		fw.metricsRecorder.AddExtensionIntegerValue(metricKey(scopeID, key), getMetric())
	}
}

func (fw *FileFilter) recordBoolMetricLazy(scopeID, key string, getMetric func() bool) {
	if fw.metricsRecorder != nil {
		fw.metricsRecorder.AddExtensionBoolValue(metricKey(scopeID, key), getMetric())
	}
}

// metricKey namespaces a metric under the scope of the filter run that recorded it, so that
// repeated runs do not overwrite each other in a recorder that keeps only the last value per key.
func metricKey(scopeID, key string) string {
	return fmt.Sprintf("%s.%s.%s", metricFileFilterPrefix, scopeID, key)
}

func newFileFilterMetricScopeID() string {
	return fmt.Sprintf("%d", nextFileFilterMetricScopeID.Add(1))
}

// NewFileFilter creates a FileFilter rooted at path. Without WithConfig, feature flags default to disabled (legacy).
func NewFileFilter(path string, logger *zerolog.Logger, options ...FileFilterOption) *FileFilter {
	filter := &FileFilter{
		path:            path,
		defaultRules:    []string{"**/.git/**"},
		logger:          logger,
		max_threads:     int64(runtime.NumCPU()),
		dotSnykSections: []DotSnykExcludeSectionName{DotSnykExcludeCode, DotSnykExcludeGlobal}, // init default with DotSnykExcludeCode and DotSnykExcludeGlobal to keep it backwards compatible
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
	// Both feature flags change how rules are built (see buildGlobs), so the rules scope reports
	// them alongside the build duration rather than relying on a GetFilteredFiles run that may
	// never happen or may read a different flag value.
	scopeID := newFileFilterMetricScopeID()
	start := time.Now()
	defer fw.recordMetricLazy(scopeID, metricFileFilterRulesBuildDurationMs, func() int {
		return int(time.Since(start).Milliseconds())
	})
	fw.recordBoolMetricLazy(scopeID, metricFileFilterMetacharacterFix, func() bool {
		return fw.config.GetBool(FF_FILE_FILTER_METACHARACTER_FIX)
	})
	fw.recordBoolMetricLazy(scopeID, metricFileFilterRespectTrackedFiles, func() bool {
		return fw.config.GetBool(FF_GITIGNORE_RESPECT_TRACKED_FILES)
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

	return append(fw.defaultRules, globs...), nil
}

// GetFilteredFiles returns a filtered channel of filepaths from a given channel of filespaths and glob patterns to filter on
func (fw *FileFilter) GetFilteredFiles(filesCh chan string, globs []string) chan string {
	// Each run reports under its own scope, so that concurrent or repeated runs of this FileFilter
	// neither race on shared state nor overwrite each other's values in the recorder.
	runScopeID := newFileFilterMetricScopeID()

	var filteredFilesCh = make(chan string)

	go func() {
		ctx := context.Background()
		availableThreads := semaphore.NewWeighted(fw.max_threads)
		start := time.Now()
		var resolvedFileCount atomic.Int64

		defer close(filteredFilesCh)

		// Building the predicate is part of the run: with FF_GITIGNORE_RESPECT_TRACKED_FILES it
		// opens the repository and reads the git index, so it is timed alongside the filtering.
		var isFileExcluded func(string) bool
		var trackedFilesKeptCount atomic.Int64
		if fw.config.GetBool(FF_GITIGNORE_RESPECT_TRACKED_FILES) {
			isFileExcluded = fw.trackedFileExclusionPredicate(globs, &trackedFilesKeptCount)
		} else {
			globPatternMatcher := gitignore.CompileIgnoreLines(globs...)
			isFileExcluded = func(filePath string) bool {
				return globPatternMatcher.MatchesPath(filePath)
			}
		}

		// iterate the filesToFilter channel
		for file := range filesCh {
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

		fw.recordBoolMetricLazy(runScopeID, metricFileFilterMetacharacterFix, func() bool {
			return fw.config.GetBool(FF_FILE_FILTER_METACHARACTER_FIX)
		})
		fw.recordBoolMetricLazy(runScopeID, metricFileFilterRespectTrackedFiles, func() bool {
			return fw.config.GetBool(FF_GITIGNORE_RESPECT_TRACKED_FILES)
		})
		fw.recordMetricLazy(runScopeID, metricFileFilterDurationMs, func() int {
			return int(time.Since(start).Milliseconds())
		})
		fw.recordMetricLazy(runScopeID, metricFileFilterSurvivingFileCount, func() int {
			return int(resolvedFileCount.Load())
		})
		fw.recordMetricLazy(runScopeID, metricFileFilterTrackedFilesKeptCount, func() int {
			return int(trackedFilesKeptCount.Load())
		})
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
func (fw *FileFilter) trackedFileExclusionPredicate(globs []string, keptCount *atomic.Int64) func(string) bool {
	var nonGitignoreGlobs []string
	allGlobs := make([]string, 0, len(globs))
	hasGitignoreGlobs := false

	for _, glob := range globs {
		if stripped, ok := strings.CutPrefix(glob, gitIgnoreGlobPrefix); ok {
			allGlobs = append(allGlobs, stripped)
			hasGitignoreGlobs = true
		} else {
			nonGitignoreGlobs = append(nonGitignoreGlobs, glob)
			allGlobs = append(allGlobs, glob)
		}
	}

	allMatcher := gitignore.CompileIgnoreLines(allGlobs...)
	defaultPredicate := func(file string) bool {
		return allMatcher.MatchesPath(filepath.ToSlash(file))
	}

	if !hasGitignoreGlobs {
		return defaultPredicate
	}

	dotGitDir, worktreeRoot, err := findDotGit(fw.path)
	if err != nil {
		fw.logger.Debug().Msgf("failed to find .git directory: %v", err)
		return defaultPredicate
	}

	trackedFiles, err := readTrackedFileNames(dotGitDir)
	if err != nil {
		fw.logger.Debug().Msgf("failed to read git index: %v", err)
		return defaultPredicate
	}

	repoRoot, err := matchingRepositoryRoot(fw.path, worktreeRoot)
	if err != nil {
		fw.logger.Debug().Msgf("failed to resolve git repository root: %v", err)
		return defaultPredicate
	}

	repoPrefix := filepath.ToSlash(repoRoot) + "/"

	var nonGitignoreMatcher *gitignore.GitIgnore
	if len(nonGitignoreGlobs) > 0 {
		nonGitignoreMatcher = gitignore.CompileIgnoreLines(nonGitignoreGlobs...)
	}

	return func(file string) bool {
		normalizedPath := filepath.ToSlash(file)
		if !allMatcher.MatchesPath(normalizedPath) {
			return false
		}
		relPath := strings.TrimPrefix(normalizedPath, repoPrefix)
		if _, tracked := trackedFiles[relPath]; tracked {
			if nonGitignoreMatcher != nil && nonGitignoreMatcher.MatchesPath(normalizedPath) {
				return true
			}
			keptCount.Add(1)
			return false
		}
		return true
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

// findDotGit walks up from startPath looking for a .git directory, mirroring go-git's
// DetectDotGit: true. It returns the .git path and the worktree root (its parent).
func findDotGit(startPath string) (dotGitDir string, worktreeRoot string, err error) {
	dir, err := filepath.Abs(startPath)
	if err != nil {
		return "", "", err
	}

	for {
		candidate := filepath.Join(dir, ".git")
		info, statErr := os.Stat(candidate)
		if statErr == nil {
			if info.IsDir() {
				return candidate, dir, nil
			}
			resolved, resolveErr := resolveGitlink(candidate, dir)
			if resolveErr != nil {
				return "", "", resolveErr
			}
			return resolved, dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", "", fmt.Errorf("no .git directory found from %s", startPath)
		}
		dir = parent
	}
}

// resolveGitlink reads a gitlink file (used for worktrees/submodules) and returns the .git
// directory it points to.
func resolveGitlink(gitlinkPath, baseDir string) (string, error) {
	content, err := os.ReadFile(gitlinkPath)
	if err != nil {
		return "", err
	}

	const prefix = "gitdir:"
	line := strings.TrimSpace(string(content))
	if !strings.HasPrefix(line, prefix) {
		return "", fmt.Errorf("malformed .git link file %s", gitlinkPath)
	}

	target := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	if !filepath.IsAbs(target) {
		target = filepath.Join(baseDir, target)
	}
	return filepath.Clean(target), nil
}

const (
	gitIndexEntryHeaderLength = 62
	gitIndexEntryExtendedFlag = 0x4000
	gitIndexNameMask          = 0xfff
)

// readTrackedFileNames parses the git index binary format directly, reading only file names and
// discarding every other entry field (hash, timestamps, mode, ...). This avoids go-git's full
// Entry deserialization, which is significant overhead on repositories with many tracked files.
func readTrackedFileNames(dotGitPath string) (map[string]struct{}, error) {
	f, err := os.Open(filepath.Join(dotGitPath, "index"))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := bufio.NewReader(f)

	var header [12]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	if string(header[:4]) != "DIRC" {
		return nil, fmt.Errorf("git index: missing DIRC signature")
	}

	version := binary.BigEndian.Uint32(header[4:8])
	if version < 2 || version > 4 {
		return nil, fmt.Errorf("git index: unsupported version %d", version)
	}
	entryCount := binary.BigEndian.Uint32(header[8:12])

	names := make(map[string]struct{}, entryCount)
	entryHeader := make([]byte, gitIndexEntryHeaderLength)
	var lastName string

	for i := uint32(0); i < entryCount; i++ {
		if _, err := io.ReadFull(r, entryHeader); err != nil {
			return nil, err
		}
		flags := binary.BigEndian.Uint16(entryHeader[60:62])
		consumedHeader := gitIndexEntryHeaderLength

		if version >= 3 && flags&gitIndexEntryExtendedFlag != 0 {
			if _, err := r.Discard(2); err != nil {
				return nil, err
			}
			consumedHeader += 2
		}

		name, nameConsumed, err := readGitIndexEntryName(r, version, flags, lastName)
		if err != nil {
			return nil, err
		}

		names[name] = struct{}{}
		lastName = name

		if version != 4 {
			entrySize := consumedHeader + len(name)
			padLen := 8 - entrySize%8
			padLen -= nameConsumed - len(name)
			if padLen > 0 {
				if _, err := r.Discard(padLen); err != nil {
					return nil, err
				}
			}
		}
	}

	return names, nil
}

// readGitIndexEntryName reads a single entry's name, returning the name and the number of bytes
// consumed from the stream for the name portion (used to compute v2/v3 padding).
func readGitIndexEntryName(r *bufio.Reader, version uint32, flags uint16, lastName string) (name string, consumed int, err error) {
	if version == 4 {
		stripLen, err := readGitVarInt(r)
		if err != nil {
			return "", 0, err
		}
		if stripLen < 0 || int(stripLen) > len(lastName) {
			return "", 0, fmt.Errorf("git index: invalid v4 name strip length %d", stripLen)
		}
		suffix, err := r.ReadString(0)
		if err != nil {
			return "", 0, err
		}
		name = lastName[:len(lastName)-int(stripLen)] + strings.TrimSuffix(suffix, "\x00")
		return name, 0, nil
	}

	nameLen := int(flags & gitIndexNameMask)
	if nameLen == gitIndexNameMask {
		suffix, err := r.ReadString(0)
		if err != nil {
			return "", 0, err
		}
		name = strings.TrimSuffix(suffix, "\x00")
		return name, len(name) + 1, nil
	}

	buf := make([]byte, nameLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", 0, err
	}
	return string(buf), nameLen, nil
}

// readGitVarInt reads a Git VLQ-encoded integer, used by the v4 index format for name-prefix
// strip lengths.
func readGitVarInt(r io.ByteReader) (int64, error) {
	c, err := r.ReadByte()
	if err != nil {
		return 0, err
	}

	v := int64(c & 0x7f)
	for c&0x80 != 0 {
		v++
		c, err = r.ReadByte()
		if err != nil {
			return 0, err
		}
		v = (v << 7) + int64(c&0x7f)
	}
	return v, nil
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
