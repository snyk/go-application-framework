package file_filter

import (
	"github.com/rs/zerolog"
	gitignore "github.com/sabhiram/go-gitignore"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// For .gitignore, .snyk etc
type IgnoresFileFilter struct {
	ignores *gitignore.GitIgnore
}

func NewIgnoresFileFilterFromIgnoreFiles(path string, ignoresFiles []string, logger *zerolog.Logger) (*IgnoresFileFilter, error) {
	ff := FileFilter{
		path:        path,
		logger:      logger,
		max_threads: int64(runtime.NumCPU()),
	}

	files := ff.GetAllFiles()
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
