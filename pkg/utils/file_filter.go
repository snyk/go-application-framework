package utils

import (
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	gitignore "github.com/sabhiram/go-gitignore"
)

type FileFilter struct {
	path         string
	defaultRules []string
	logger       *zerolog.Logger
}

func NewFileFilter(path string, logger *zerolog.Logger) *FileFilter {
	return &FileFilter{
		path:         path,
		defaultRules: []string{"**/.git/**"},
		logger:       logger,
	}
}

// GetAllFiles traverses a given dir path and fetches all filesToFilter in the directory
func (fw *FileFilter) GetAllFiles() chan string {
	var filesCh = make(chan string)
	go func() {
		defer close(filesCh)
		err := filepath.WalkDir(fw.path, func(path string, d fs.DirEntry, err error) error {
			if !d.IsDir() && err == nil {
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
		defer close(filteredFilesCh)
		// iterate the filesToFilter channel
		for file := range filesCh {
			// filesToFilter that do not match the glob pattern are filtered
			if !globPatternMatcher.MatchesPath(file) {
				filteredFilesCh <- file
			}
		}
	}()

	return filteredFilesCh
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
	type DotSnykRules struct {
		Exclude struct {
			Code   []string `yaml:"code"`
			Global []string `yaml:"global"`
		} `yaml:"exclude"`
	}

	var rules DotSnykRules
	err := yaml.Unmarshal(content, &rules)
	if err != nil {
		fw.logger.Error().Msgf("parse .snyk failed: %v", err)
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
