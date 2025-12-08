package utils

import (
	"context"
	"fmt"
	"github.com/rs/zerolog"
	gitignore "github.com/sabhiram/go-gitignore"
	"golang.org/x/sync/semaphore"
	"gopkg.in/yaml.v3"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type Filterable interface {
	Filter(path string) bool
}

type FileFilter struct {
	path             string
	logger           *zerolog.Logger
	FilterStrategies []Filterable
	max_threads      int64
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

func WithFileFilterStrategies(strategies []Filterable) FileFilterOption {
	return func(filter *FileFilter) error {
		filter.FilterStrategies = append(filter.FilterStrategies, strategies...)
		return nil
	}
}

func WithDefaultRulesFilter() FileFilterOption {
	return func(filter *FileFilter) error {
		defaultFilter, err := NewIgnoresFileFilterFromGlobs([]string{"**/.git/**"})
		if err != nil {
			return fmt.Errorf("error creating default filter: %w", err)

		}

		filter.FilterStrategies = append(filter.FilterStrategies, defaultFilter)
		return nil
	}
}

func NewFileFilter(path string, logger *zerolog.Logger, options ...FileFilterOption) *FileFilter {
	filter := &FileFilter{
		path:        path,
		logger:      logger,
		max_threads: int64(runtime.NumCPU()),
	}

	for _, option := range options {
		err := option(filter)
		if err != nil {
			logger.Err(err).Msg("failed to apply option for FileFilter")
		}
	}

	return filter
}

// GetFilteredFiles returns a filtered channel of filepaths from a given channel of filespaths and glob patterns to filter on
func (fw *FileFilter) GetFilteredFiles() chan string {
	filesCh := getAllFiles(fw.path, fw.logger)
	
	var filteredFilesCh = make(chan string)
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
				// filesToFilter that do not match the filter list are excluded
				keepFile := true
				for _, filter := range fw.FilterStrategies {
					if filter.Filter(f) {
						keepFile = false
						break
					}
				}

				if keepFile {
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

// Default file filter for gitignore like filters -> refactored implementation

// For .gitignore, .snyk etc
type IgnoresFileFilter struct {
	ignores *gitignore.GitIgnore
}

func NewIgnoresFileFilterFromIgnoreFiles(path string, ignoresFiles []string, logger *zerolog.Logger) (*IgnoresFileFilter, error) {
	files := getAllFiles(path, logger)
	rules, err := getRules(files, ignoresFiles, logger)
	if err != nil {
		return nil, err
	}

	return &IgnoresFileFilter{ignores: gitignore.CompileIgnoreLines(rules...)}, nil
}

// For any other glob like filtering
func NewIgnoresFileFilterFromGlobs(globs []string) (*IgnoresFileFilter, error) {
	return &IgnoresFileFilter{ignores: gitignore.CompileIgnoreLines(globs...)}, nil
}

func (ff *IgnoresFileFilter) Filter(path string) bool {
	if ff.ignores == nil {
		return false
	}
	return ff.ignores.MatchesPath(path)
}

// getRules builds a list of glob patterns that can be used to filter filesToFilter
func getRules(files chan string, ruleFiles []string, logger *zerolog.Logger) ([]string, error) {
	defaultRules := []string{"**/.git/**"}
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
	globs, err := buildGlobs(ignoreFiles, logger)
	if err != nil {
		return nil, err
	}

	return append(defaultRules, globs...), nil
}

// GetAllFiles traverses a given dir path and fetches all filesToFilter in the directory
func getAllFiles(path string, logger *zerolog.Logger) chan string {
	var filesCh = make(chan string)
	go func() {
		defer close(filesCh)

		err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if !d.IsDir() {
				filesCh <- path
			}

			return err
		})
		if err != nil {
			logger.Error().Msgf("walk dir failed: %v", err)
		}
	}()

	return filesCh
}

// buildGlobs iterates a list of ignore filesToFilter and returns a list of glob patterns that can be used to test for ignored filesToFilter
func buildGlobs(ignoreFiles []string, logger *zerolog.Logger) ([]string, error) {
	var globs = make([]string, 0)
	for _, ignoreFile := range ignoreFiles {
		var content []byte
		content, err := os.ReadFile(ignoreFile)
		if err != nil {
			return nil, err
		}

		if filepath.Base(ignoreFile) == ".snyk" { // .snyk files are yaml files and should be parsed differently
			parsedRules := parseDotSnykFile(content, filepath.Dir(ignoreFile), logger)
			globs = append(globs, parsedRules...)
		} else { // .gitignore, .dcignore, etc. are just a list of ignore rules
			parsedRules := parseIgnoreFile(content, filepath.Dir(ignoreFile))
			globs = append(globs, parsedRules...)
		}
	}

	return globs, nil
}

// parseDotSnykFile builds a list of glob patterns from a given .snyk style file
func parseDotSnykFile(content []byte, filePath string, logger *zerolog.Logger) []string {
	type DotSnykRules struct {
		Exclude struct {
			Code   []string `yaml:"code"`
			Global []string `yaml:"global"`
		} `yaml:"exclude"`
	}

	var rules DotSnykRules
	err := yaml.Unmarshal(content, &rules)
	if err != nil {
		logger.Error().Msgf("parse .snyk failed: %v", err)
		return nil
	}

	var globs []string
	for _, codeRule := range rules.Exclude.Code {
		globs = append(globs, parseIgnoreRuleToGlobs(codeRule, filePath)...)
	}
	for _, codeRule := range rules.Exclude.Global {
		globs = append(globs, parseIgnoreRuleToGlobs(codeRule, filePath)...)
	}

	return globs
}

// parseIgnoreFile builds a list of glob patterns from a given .gitignore style file
func parseIgnoreFile(content []byte, filePath string) []string {
	var ignores []string
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		globs := parseIgnoreRuleToGlobs(line, filePath)
		ignores = append(ignores, globs...)
	}
	return ignores
}

// parseIgnoreRuleToGlobs contains the business logic to build glob patterns from a given ignore file
func parseIgnoreRuleToGlobs(rule string, filePath string) (globs []string) {
	// Mappings from .gitignore format to glob format:
	// `/foo/` => `/foo/**` (meaning: Ignore root (not sub) foo dir and its paths underneath.)
	// `/foo`	=> `/foo/**`, `/foo` (meaning: Ignore root (not sub) file and dir and its paths underneath.)
	// `foo/` => `**/foo/**` (meaning: Ignore (root/sub) foo dirs and their paths underneath.)
	// `foo` => `**/foo/**`, `foo` (meaning: Ignore (root/sub) foo filesToFilter and dirs and their paths underneath.)
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
			globs = append(globs, filepath.ToSlash(prefix+filepath.Join(baseDir, rule, all)))
		}
		// case `/foo` => `{baseDir}/foo`
		// case `**/foo` => `{baseDir}/**/foo`
		// case `/foo/**` => `{baseDir}/foo/**`
		// case `**/foo/**` => `{baseDir}/**/foo/**`
		if !endingSlash {
			globs = append(globs, filepath.ToSlash(prefix+filepath.Join(baseDir, rule)))
		}
	} else {
		// case `foo/`, `foo` => `{baseDir}/**/foo/**`
		if !endingGlobstar {
			globs = append(globs, filepath.ToSlash(prefix+filepath.Join(baseDir, all, rule, all)))
		}
		// case `foo` => `{baseDir}/**/foo`
		// case `foo/**` => `{baseDir}/**/foo/**`
		if !endingSlash {
			globs = append(globs, filepath.ToSlash(prefix+filepath.Join(baseDir, all, rule)))
		}
	}
	return globs
}
