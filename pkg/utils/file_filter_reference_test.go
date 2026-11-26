package utils

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-git/go-git/v5"
	gitignore "github.com/sabhiram/go-gitignore"
)

// referenceExclusionPredicate is the exclusion predicate GetFilteredFiles had before folders were
// matched once per folder: every file is matched against every rule. Tests compare GetFilteredFiles
// with it.
func (fw *FileFilter) referenceExclusionPredicate(globs []string) func(string) bool {
	if fw.config.GetBool(FF_GITIGNORE_RESPECT_TRACKED_FILES) {
		return fw.referenceTrackedFileExclusionPredicate(globs)
	}
	globPatternMatcher := gitignore.CompileIgnoreLines(globs...)
	return func(filePath string) bool {
		return globPatternMatcher.MatchesPath(filePath)
	}
}

// referenceTrackedFileExclusionPredicate is the exclusion predicate GetFilteredFiles had
// (from origin/main before folders were matched once per folder) when
// FF_GITIGNORE_RESPECT_TRACKED_FILES is enabled. It matches every file against every rule.
func (fw *FileFilter) referenceTrackedFileExclusionPredicate(globs []string) func(string) bool {
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

// referenceFilteredFiles returns the files that referenceExclusionPredicate keeps, in order, without
// the symlinks, files inside a symlinked folder below the filter's path, and files with a .git path element.
func (fw *FileFilter) referenceFilteredFiles(files []string, globs []string) []string {
	isExcluded := fw.referenceExclusionPredicate(globs)
	var kept []string
	for _, file := range files {
		if !isExcluded(file) && !referenceIsLinked(fw.path, file) && !referenceInGitFolder(file) {
			kept = append(kept, file)
		}
	}
	return kept
}

func referenceInGitFolder(file string) bool {
	return slices.Contains(strings.Split(filepath.ToSlash(file), "/"), ".git")
}

// referenceIsLinked reports whether file, or a folder between root and file, is a symlink.
func referenceIsLinked(root, file string) bool {
	paths := []string{file}
	if rel, err := filepath.Rel(root, file); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		parts := strings.Split(rel, string(filepath.Separator))
		for i := 1; i < len(parts); i++ {
			paths = append(paths, filepath.Join(append([]string{root}, parts[:i]...)...))
		}
	}
	for _, path := range paths {
		if info, err := os.Lstat(path); err == nil && info.Mode()&fs.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

func filesChannel(files []string) chan string {
	ch := make(chan string, len(files))
	for _, file := range files {
		ch <- file
	}
	close(ch)
	return ch
}
