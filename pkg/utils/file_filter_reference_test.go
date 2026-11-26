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

// referenceExclusionPredicate is the exclusion predicate GetFilteredFiles had before excluded-folder
// tracking: it matches target using the matcher the old code chose for file. Tests compare
// GetFilteredFiles with it.
func (fw *FileFilter) referenceExclusionPredicate(globs []string) func(file, target string) bool {
	if fw.config.GetBool(FF_GITIGNORE_RESPECT_TRACKED_FILES) {
		return fw.referenceTrackedFileExclusionPredicate(globs)
	}
	globPatternMatcher := gitignore.CompileIgnoreLines(globs...)
	return func(_, target string) bool {
		return globPatternMatcher.MatchesPath(target)
	}
}

// referenceTrackedFileExclusionPredicate is the exclusion predicate GetFilteredFiles had
// (from origin/main before excluded-folder tracking) when FF_GITIGNORE_RESPECT_TRACKED_FILES
// is enabled. It matches target using the matcher the old code chose for file.
func (fw *FileFilter) referenceTrackedFileExclusionPredicate(globs []string) func(file, target string) bool {
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
	defaultPredicate := func(_, target string) bool {
		return allMatcher.MatchesPath(filepath.ToSlash(target))
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

	return func(file, target string) bool {
		normalizedPath := filepath.ToSlash(target)
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

// referenceFolders returns the folders between root and file, outermost first.
func referenceFolders(root, file string) []string {
	rel, err := filepath.Rel(root, file)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil
	}
	parts := strings.Split(rel, string(filepath.Separator))
	folders := make([]string, 0, len(parts)-1)
	for i := 1; i < len(parts); i++ {
		folders = append(folders, filepath.Join(append([]string{root}, parts[:i]...)...))
	}
	return folders
}

// referenceInExcludedFolder reports whether the rules match a folder between root and file: git never
// re-includes a file inside an excluded folder.
func referenceInExcludedFolder(root, file string, isExcluded func(file, target string) bool) bool {
	return slices.ContainsFunc(referenceFolders(root, file), func(folder string) bool { return isExcluded(file, folder) })
}

// referenceFilteredFiles returns the files the old full match keeps, in order. With FF_FILE_FILTER_GIT_SEMANTICS
// it also drops the deliberate differences: files inside a folder below the filter's path that the rules match,
// symlinks and files inside a symlinked folder, and paths with a .git element.
func (fw *FileFilter) referenceFilteredFiles(files []string, globs []string) []string {
	isExcluded := fw.referenceExclusionPredicate(globs)
	gitSemantics := fw.gitSemantics()
	var kept []string
	for _, file := range files {
		if isExcluded(file, file) {
			continue
		}
		if gitSemantics && (referenceInExcludedFolder(fw.path, file, isExcluded) || referenceIsLinked(fw.path, file) || referenceInGitFolder(file)) {
			continue
		}
		kept = append(kept, file)
	}
	return kept
}

func referenceInGitFolder(file string) bool {
	return slices.Contains(strings.Split(filepath.ToSlash(file), "/"), ".git")
}

// referenceIsLinked reports whether file, or a folder between root and file, is a symlink.
func referenceIsLinked(root, file string) bool {
	for _, path := range append(referenceFolders(root, file), file) {
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
