package utils

import (
	"os"
	"path"
	"path/filepath"

	"github.com/go-git/go-git/v5"
)

// globWalk lists the files a scan should send, in one pass over the scan root.
type globWalk struct {
	fw                     *FileFilter
	enableMetacharacterFix bool
	// tracked holds the repository-relative slash paths of tracked files and of every folder above
	// them. It is nil when tracked files are not respected.
	tracked          map[string]bool
	files            []string
	matchersCompiled int
}

// globWalkFiles returns the files to send and how many matchers were compiled to decide them.
func (fw *FileFilter) globWalkFiles(respectTrackedFiles bool) ([]string, int) {
	w := &globWalk{
		fw:                     fw,
		enableMetacharacterFix: fw.config.GetBool(FF_FILE_FILTER_METACHARACTER_FIX),
	}

	relRoot := "."
	if respectTrackedFiles {
		w.tracked, relRoot = fw.globWalkTrackedPaths()
	}

	root := &globRules{allGlobs: fw.defaultRules, snykGlobs: fw.defaultRules}
	root.all = w.compile(root.allGlobs)
	root.snyk = w.compile(root.snykGlobs)

	w.walk(fw.path, relRoot, root, false)

	return w.files, w.matchersCompiled
}

// walk visits the entries of dir in name order, as filepath.WalkDir does. ignored is set when a
// folder above dir is git-ignored, so dir can only contribute tracked files.
func (w *globWalk) walk(dir, relDir string, rules *globRules, ignored bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		w.fw.logger.Error().Msgf("walk dir failed: %v", err)
		return
	}

	rules = w.extendRules(dir, entries, rules, !ignored)

	for _, entry := range entries {
		name := entry.Name()
		fullPath := filepath.Join(dir, name)
		relPath := path.Join(relDir, name)

		switch {
		case entry.IsDir() && name == ".git":
			// Git's own folder is never sent.
		case entry.IsDir():
			w.visitDir(fullPath, relPath, rules, ignored)
		default:
			// Symlinks are not directories, so they are listed as files and never followed.
			w.visitFile(fullPath, relPath, rules, ignored)
		}
	}
}

// visitDir walks a folder unless a snyk rule excludes it, or git ignores it and no tracked file lies
// below it. Git-ignored folders are walked only so their tracked files are found.
func (w *globWalk) visitDir(fullPath, relPath string, rules *globRules, ignored bool) {
	slashPath := filepath.ToSlash(fullPath)
	if rules.snyk.MatchesPath(slashPath) {
		return
	}

	gitIgnored := rules.all.MatchesPath(slashPath)
	if !w.isTracked(relPath) && (ignored || gitIgnored) {
		return
	}

	w.walk(fullPath, relPath, rules, ignored || gitIgnored)
}

// visitFile lists a file that no rule excludes. A tracked file is judged by the snyk rules alone,
// because .gitignore rules never exclude it. An untracked file under a git-ignored folder is not listed.
func (w *globWalk) visitFile(fullPath, relPath string, rules *globRules, ignored bool) {
	slashPath := filepath.ToSlash(fullPath)
	if w.isTracked(relPath) {
		if !rules.snyk.MatchesPath(slashPath) {
			w.files = append(w.files, fullPath)
		}
		return
	}

	if !ignored && !rules.all.MatchesPath(slashPath) {
		w.files = append(w.files, fullPath)
	}
}

func (w *globWalk) isTracked(relPath string) bool {
	return w.tracked[relPath]
}

// globWalkTrackedPaths reads the git index the way trackedFileExclusionPredicate does. It returns the
// tracked paths and the scan root relative to the repository root, or nil and "." when there is no
// readable repository.
func (fw *FileFilter) globWalkTrackedPaths() (map[string]bool, string) {
	repo, err := git.PlainOpenWithOptions(fw.path, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		fw.logger.Debug().Msgf("failed to open git repository: %v", err)
		return nil, "."
	}

	worktree, err := repo.Worktree()
	if err != nil {
		fw.logger.Debug().Msgf("failed to get worktree: %v", err)
		return nil, "."
	}

	gitIndex, err := repo.Storer.Index()
	if err != nil {
		fw.logger.Debug().Msgf("failed to get git index: %v", err)
		return nil, "."
	}

	repoRoot, err := matchingRepositoryRoot(fw.path, worktree.Filesystem.Root())
	if err != nil {
		fw.logger.Debug().Msgf("failed to resolve git repository root: %v", err)
		return nil, "."
	}

	relRoot, err := filepath.Rel(repoRoot, fw.path)
	if err != nil {
		fw.logger.Debug().Msgf("failed to relate scan root to repository root: %v", err)
		return nil, "."
	}

	tracked := make(map[string]bool, len(gitIndex.Entries))
	for _, entry := range gitIndex.Entries {
		tracked[entry.Name] = true
		// Stop at the first folder already recorded: its own ancestors were recorded with it.
		for dir := path.Dir(entry.Name); dir != "." && !tracked[dir]; dir = path.Dir(dir) {
			tracked[dir] = true
		}
	}

	return tracked, filepath.ToSlash(relRoot)
}
