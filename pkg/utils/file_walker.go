package utils

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	gitignore "github.com/sabhiram/go-gitignore"
)

type FileWalker struct {
	path string
}

func NewFileWalker(path string) *FileWalker {
	return &FileWalker{
		path: path,
	}
}

// GetAllFiles traverses a given dir path and fetches all files in the directory
func (fw *FileWalker) GetAllFiles() chan string {
	var filesCh = make(chan string)
	go func() {
		defer close(filesCh)
		_ = filepath.WalkDir(fw.path, func(path string, d fs.DirEntry, err error) error {
			if !d.IsDir() && err == nil {
				filesCh <- path
			}
			return err
		})
	}()

	return filesCh
}

// GetRules builds a list of glob patterns that can be used to filter files
func (fw *FileWalker) GetRules(ruleFiles []string) ([]string, error) {
	defaultGlob := []string{"**/.git/**", "**/.gitignore/**"}
	files := fw.GetAllFiles()

	// iterate files channel and find ignore files
	var ignoreFiles = make([]string, 0)
	for file := range files {
		for _, ruleFile := range ruleFiles {
			if strings.Contains(file, ruleFile) {
				ignoreFiles = append(ignoreFiles, file)
			}
		}
	}

	// iterate ignore files and extract glob patterns
	globs, err := fw.buildGlobs(ignoreFiles)
	if err != nil {
		return nil, err
	}

	return append(defaultGlob, globs...), nil
}

// GetFilteredFiles returns a filtered channel of filepaths from a given channel of filespaths and glob patterns to filter on
func (fw *FileWalker) GetFilteredFiles(filesCh chan string, globs []string) chan string {
	var filteredFilesCh = make(chan string)

	// create pattern matcher used to match files to glob patterns
	globPatternMatcher := gitignore.CompileIgnoreLines(globs...)

	// iterate the files channel
	go func() {
		defer close(filteredFilesCh)
		for file := range filesCh {
			// files that do not match the glob pattern are filtered
			if !globPatternMatcher.MatchesPath(file) {
				filteredFilesCh <- file
			}
		}
	}()

	return filteredFilesCh
}

// buildGlobs iterates a list of ignore files and returns a list of glob patterns that can be used to test for ignored files
func (fw *FileWalker) buildGlobs(ignoreFiles []string) ([]string, error) {
	var globs = make([]string, 0)
	for _, ignoreFile := range ignoreFiles {
		var content []byte
		content, err := os.ReadFile(ignoreFile)
		if err != nil {
			return nil, err
		}
		// .gitignore, .dcignore, etc. are just a list of ignore rules
		parsedRules := fw.parseIgnoreFile(content, filepath.Dir(ignoreFile))
		globs = append(globs, parsedRules...)
	}

	return globs, nil
}

// parseIgnoreFile builds a list of glob patterns from a given ignore file
func (fw *FileWalker) parseIgnoreFile(content []byte, filePath string) (ignores []string) {
	ignores = []string{}
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		globs := fw.parseIgnoreRuleToGlobs(line, filePath)
		ignores = append(ignores, globs...)
	}
	return ignores
}

// parseIgnoreRuleToGlobs contains the business logic to build glob patterns from a given ignore file
func (fw *FileWalker) parseIgnoreRuleToGlobs(rule string, filePath string) (globs []string) {
	// Mappings from .gitignore format to glob format:
	// `/foo/` => `/foo/**` (meaning: Ignore root (not sub) foo dir and its paths underneath.)
	// `/foo`	=> `/foo/**`, `/foo` (meaning: Ignore root (not sub) file and dir and its paths underneath.)
	// `foo/` => `**/foo/**` (meaning: Ignore (root/sub) foo dirs and their paths underneath.)
	// `foo` => `**/foo/**`, `foo` (meaning: Ignore (root/sub) foo files and dirs and their paths underneath.)
	prefix := ""
	const negation = "!"
	const slash = "/"
	const all = "**"
	baseDir := filepath.Dir(filePath)
	baseDir = filepath.ToSlash(filePath)

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
