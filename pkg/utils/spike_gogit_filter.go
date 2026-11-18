package utils

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	gitignore "github.com/go-git/go-git/v6/plumbing/format/gitignore"
	"github.com/rs/zerolog"
)

type goGitFilterOptions struct {
	// ReadParentRuleFiles also reads the .gitignore files between the repository root and the scan root.
	ReadParentRuleFiles bool
}

// goGitFilter returns the files under scanRoot that a scan uploads, in one directory walk. Files
// are matched with git's own semantics; tracked files stay in even where a .gitignore excludes
// them, but never where a .snyk or .dcignore rule does. Symlinks are not followed and not listed.
func goGitFilter(scanRoot string, logger *zerolog.Logger, opts goGitFilterOptions) ([]string, error) {
	repo := locateRepository(scanRoot, logger)

	gitBase := append(readGlobalExcludePatterns(), repo.infoExcludePatterns()...)
	snykBase := []gitignore.Pattern{gitignore.ParsePattern(dotGitName, nil)}

	walker := &goGitWalker{
		logger:   logger,
		sections: []DotSnykExcludeSectionName{DotSnykExcludeCode, DotSnykExcludeGlobal},
		tracked:  repo.trackedFilesAndDirs,
	}

	prefix := repo.scanRootComponents
	if len(prefix) == 0 {
		// The walk root has no parent to descend from, so its own rules join the base.
		entries, err := os.ReadDir(scanRoot)
		if err != nil {
			return nil, err
		}
		gitOwn := walker.gitignoreReader(scanRoot, entries, nil)
		snykOwn := walker.snykReader(scanRoot, entries, nil)
		gitBase = appendOwn(gitBase, gitOwn)
		snykBase = appendOwn(snykBase, snykOwn)
	}

	gitScope := gitignore.NewScope(gitBase)
	if opts.ReadParentRuleFiles && len(prefix) > 0 {
		gitScope = walker.scopeWithParentRules(repo.root, prefix, gitBase)
	}

	walker.walk(scanRoot, prefix, gitScope, gitignore.NewScope(snykBase))

	return walker.files, nil
}

func appendOwn(base []gitignore.Pattern, own func() ([]gitignore.Pattern, error)) []gitignore.Pattern {
	if own == nil {
		return base
	}
	patterns, err := own()
	if err != nil {
		return base
	}

	return append(base, patterns...)
}

type goGitWalker struct {
	logger   *zerolog.Logger
	sections []DotSnykExcludeSectionName
	tracked  map[string]struct{}
	files    []string
}

// scopeWithParentRules builds the git scope at the scan root's parent by descending from the
// repository root through every folder above the scan root, reading each one's .gitignore.
func (w *goGitWalker) scopeWithParentRules(repoRoot string, prefix []string, base []gitignore.Pattern) *gitignore.Scope {
	rootEntries, err := os.ReadDir(repoRoot)
	if err != nil {
		w.logger.Debug().Msgf("failed to read repository root: %v", err)
		return gitignore.NewScope(base)
	}
	rootOwn := w.gitignoreReader(repoRoot, rootEntries, nil)
	scope := gitignore.NewScope(appendOwn(base, rootOwn))

	dir := repoRoot
	for depth := 1; depth < len(prefix); depth++ {
		dir = filepath.Join(dir, prefix[depth-1])
		entries, err := os.ReadDir(dir)
		if err != nil {
			w.logger.Debug().Msgf("failed to read parent folder %s: %v", dir, err)
			continue
		}
		own := w.gitignoreReader(dir, entries, prefix[:depth])
		scope = w.descend(scope, prefix[:depth], own)
	}

	return scope
}

func (w *goGitWalker) descend(scope *gitignore.Scope, folder []string, own func() ([]gitignore.Pattern, error)) *gitignore.Scope {
	descended, err := scope.Descend(folder, own)
	if err != nil {
		w.logger.Debug().Msgf("failed to read rule file in %s: %v", strings.Join(folder, "/"), err)
		return scope
	}

	return descended
}

// gitignoreReader returns nil when the folder has no .gitignore, so Scope.Descend skips the read.
func (w *goGitWalker) gitignoreReader(dir string, entries []fs.DirEntry, folder []string) func() ([]gitignore.Pattern, error) {
	if !hasRegularFile(entries, gitignoreFileName) {
		return nil
	}

	return func() ([]gitignore.Pattern, error) {
		return readGitignorePatterns(filepath.Join(dir, gitignoreFileName), folder)
	}
}

func (w *goGitWalker) snykReader(dir string, entries []fs.DirEntry, folder []string) func() ([]gitignore.Pattern, error) {
	hasDcignore := hasRegularFile(entries, dcignoreFileName)
	hasDotSnyk := hasRegularFile(entries, dotSnykFileName)
	if !hasDcignore && !hasDotSnyk {
		return nil
	}

	return func() ([]gitignore.Pattern, error) {
		return readSnykAndDcignorePatterns(dir, folder, hasDcignore, hasDotSnyk, w.sections, w.logger)
	}
}

func hasRegularFile(entries []fs.DirEntry, name string) bool {
	for _, entry := range entries {
		if entry.Name() == name {
			return entry.Type().IsRegular()
		}
	}

	return false
}

// walk visits dir, whose path components from the repository root (or the scan root outside a
// repository) are comps. The scopes for the walk root were already built by the caller when comps is
// empty; below that each folder derives its own.
func (w *goGitWalker) walk(dir string, comps []string, gitScope, snykScope *gitignore.Scope) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		w.logger.Debug().Msgf("skipping unreadable folder %s: %v", dir, err)
		return
	}

	if len(comps) > 0 {
		own := w.snykReader(dir, entries, comps)
		snykScope = w.descend(snykScope, comps, own)
		gitOwn := w.gitignoreReader(dir, entries, comps)
		gitScope = w.descend(gitScope, comps, gitOwn)
	}
	w.collectFiles(dir, comps, entries, gitScope, snykScope)
	w.walkSubfolders(dir, comps, entries, gitScope, snykScope)
}

func (w *goGitWalker) collectFiles(dir string, comps []string, entries []fs.DirEntry, gitScope, snykScope *gitignore.Scope) {
	// Scope.Excluded is true when this folder or an ancestor matched a git rule: only tracked files get through.
	dirIsGitIgnored := gitScope.Excluded()

	for _, entry := range entries {
		if entry.Name() == dotGitName || !entry.Type().IsRegular() {
			continue
		}

		path := childComponents(comps, entry.Name())
		if snykScope.Match(path, false) {
			continue
		}
		if w.isTracked(path) || (!dirIsGitIgnored && !gitScope.Match(path, false)) {
			w.files = append(w.files, filepath.Join(dir, entry.Name()))
		}
	}
}

func (w *goGitWalker) walkSubfolders(dir string, comps []string, entries []fs.DirEntry, gitScope, snykScope *gitignore.Scope) {
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == dotGitName {
			continue
		}

		path := childComponents(comps, entry.Name())
		if snykScope.Match(path, true) {
			continue
		}
		// Evaluated before the tracked check so the walk never skips it by short-circuit.
		subIgnored := gitScope.Match(path, true)
		if w.isTracked(path) || !subIgnored {
			w.walk(filepath.Join(dir, entry.Name()), path, gitScope, snykScope)
		}
	}
}

func (w *goGitWalker) isTracked(path []string) bool {
	if len(w.tracked) == 0 {
		return false
	}
	_, ok := w.tracked[strings.Join(path, "/")]

	return ok
}

// childComponents copies: the result is retained by Scope patterns and recursion.
func childComponents(parent []string, name string) []string {
	path := make([]string, len(parent)+1)
	copy(path, parent)
	path[len(parent)] = name

	return path
}

// repository is what the walk needs to know about the git repository around the scan root.
type repository struct {
	root string
	// scanRootComponents is the scan root's path below the repository root; empty outside a repository.
	scanRootComponents  []string
	gitDir              string
	trackedFilesAndDirs map[string]struct{}
}

func (r repository) infoExcludePatterns() []gitignore.Pattern {
	if r.gitDir == "" {
		return nil
	}
	patterns, err := readGitignorePatterns(filepath.Join(r.gitDir, "info", "exclude"), nil)
	if err != nil {
		return nil
	}

	return patterns
}

// locateRepository finds the repository containing scanRoot. Outside a repository the scan root is
// the repository root and nothing is tracked.
func locateRepository(scanRoot string, logger *zerolog.Logger) repository {
	absolute, err := filepath.Abs(scanRoot)
	if err == nil {
		absolute, err = filepath.EvalSymlinks(absolute)
	}
	if err != nil {
		return repository{root: scanRoot}
	}

	root := absolute
	for {
		if _, statErr := os.Stat(filepath.Join(root, dotGitName)); statErr == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			return repository{root: scanRoot}
		}
		root = parent
	}

	found := repository{root: root}
	if relative, relErr := filepath.Rel(root, absolute); relErr == nil && relative != "." {
		found.scanRootComponents = strings.Split(filepath.ToSlash(relative), "/")
	}
	if info, statErr := os.Stat(filepath.Join(root, dotGitName)); statErr == nil && info.IsDir() {
		found.gitDir = filepath.Join(root, dotGitName)
	}
	found.trackedFilesAndDirs = readTrackedFilesAndDirs(root, logger)

	return found
}

// readTrackedFilesAndDirs returns every path in the git index plus all of their ancestor folders.
func readTrackedFilesAndDirs(repoRoot string, logger *zerolog.Logger) map[string]struct{} {
	repo, err := git.PlainOpen(repoRoot)
	if err != nil {
		logger.Debug().Msgf("failed to open git repository: %v", err)
		return nil
	}
	index, err := repo.Storer.Index()
	if err != nil {
		logger.Debug().Msgf("failed to get git index: %v", err)
		return nil
	}

	tracked := make(map[string]struct{}, len(index.Entries))
	for _, entry := range index.Entries {
		path := entry.Name
		tracked[path] = struct{}{}
		for dir := pathDir(path); dir != ""; dir = pathDir(dir) {
			if _, seen := tracked[dir]; seen {
				break
			}
			tracked[dir] = struct{}{}
		}
	}

	return tracked
}

func pathDir(path string) string {
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		return path[:i]
	}

	return ""
}
