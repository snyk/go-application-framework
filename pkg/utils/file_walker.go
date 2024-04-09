package utils

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

// GetRules iterate a channel of filepaths and filter on rule files
func (fw *FileWalker) GetRules() ([]string, error) {
	files := fw.GetAllFiles()

	// iterate files channel and find ignore files
	var ignoreFiles = make([]string, 0)
	for file := range files {
		if strings.Contains(file, ".gitignore") {
			ignoreFiles = append(ignoreFiles, file)
		}
	}

	// iterate ignore files and extract glob patterns
	globs, err := fw.buildGlobs(ignoreFiles)
	if err != nil {
		return nil, err
	}

	return globs, nil
}

//// GetFilesFilterIgnored gets files for a given dir path and fetches all files in the directory, omitting any ignored files
//func (fw *FileWalker) GetFilesFilterIgnored(path string) (chan string, error) {
//	//// walk and get files
//	//files := fw.GetAllFiles(path)
//	//
//	//// get and parse ignore globs
//	//fw.buildGlobs()
//	//parsedIgnoreGlobs := gitignore.CompileIgnoreLines(fw.globs...)
//	//
//	//// iterate files and filter out ignored files
//	//var filteredFiles = make(chan string)
//	//go func() {
//	//	defer close(filteredFiles)
//	//	for file := range files {
//	//		fileIsIgnored := parsedIgnoreGlobs.MatchesPath(file)
//	//		if !fileIsIgnored {
//	//			fmt.Printf("HELLO WORLD: %s\n", file)
//	//			filteredFiles <- file
//	//		}
//	//	}
//	//}()
//	//return filteredFiles
//
//	files, err := fw.GetAllFiles(path)
//	if err != nil {
//		return nil, err
//	}
//
//	ignoreFiles, err := fw.GetIgnoreFiles(files)
//	if err != nil {
//		return nil, err
//	}
//
//	ignoreGlobs, err := fw.buildGlobs(ignoreFiles)
//	if err != nil {
//		return nil, err
//	}
//
//	if len(ignoreGlobs) > 0 {
//		for _, glob := range ignoreGlobs {
//			fmt.Printf("Ignore files with glob: %s\n", glob)
//		}
//	}
//
//	return nil, fmt.Errorf("GetFilesFilterIgnored() not implemented")
//}

//// GetIgnoreFiles inspects a files channel and returns supported ignore files
//func (fw *FileWalker) GetIgnoreFiles(filesCh chan string) ([]string, error) {
//	ignoreFilePaths := make([]string, 0)
//
//	for file := range filesCh {
//		for _, ignoreFile := range fw.ignoreFiles {
//			if strings.Contains(file, ignoreFile) {
//				ignoreFilePaths = append(ignoreFilePaths, file)
//			}
//		}
//	}
//
//	return ignoreFilePaths, nil
//}

//// walk traverses a given root directory
//func (fw *FileWalker) walk(path string, resultsCh chan string) error {
//	err := filepath.WalkDir(path, func(path string, d fs.DirEntry, err error) error {
//		//if d.IsDir() && err == nil {
//		//	//	check if dir has any ignoreFiles in it
//		//	for _, ignoreFile := range fw.ignoreFiles {
//		//		ignoreFilePath := filepath.Join(path, ignoreFile)
//		//		_, err := os.Stat(ignoreFilePath)
//		//		if err == nil {
//		//			//	dir contains valid ignore file
//		//			fmt.Printf("Valid ignorefile: %s\n", ignoreFilePath)
//		//			fw.ignoreFilePaths = append(fw.ignoreFilePaths, ignoreFilePath)
//		//		}
//		//	}
//		//}
//
//		if !d.IsDir() && err == nil {
//			resultsCh <- path
//		}
//		return nil
//	})
//
//	if err != nil {
//		fw.logger.Error().Err(err)
//	}
//
//	return nil
//}

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
