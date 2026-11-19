package utils

import (
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/git-pkgs/gitignore"
	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog"
)

// gitPkgsWalk lists the files a scan sends in one pass over the tree.
type gitPkgsWalk struct {
	// root is the repository root, or the scan root outside a repository. Every rule scope is relative to it.
	root string
	// tracked holds the index entries and each ancestor folder of them, as root-relative slash paths.
	tracked map[string]bool
	// git holds .gitignore rules. Its bottom layers are the base rules: global excludes, info/exclude and
	// parent .gitignore files.
	git gitPkgsRuleStack
	// snyk holds .snyk and .dcignore rules. They are a separate stack because git never reads them, and
	// they exclude tracked files too.
	snyk     gitPkgsRuleStack
	sections []DotSnykExcludeSectionName
	logger   *zerolog.Logger
	files    []string
}

// gitPkgsScan returns the absolute paths of the files that survive filtering under scanRoot.
func gitPkgsScan(scanRoot string, readParentRules bool) []string {
	logger := zerolog.Nop()
	absRoot, err := filepath.Abs(scanRoot)
	if err != nil {
		return nil
	}

	w, rel := newGitPkgsWalk(absRoot, readParentRules, &logger)
	w.walk(absRoot, rel, false)

	return w.files
}

// newGitPkgsWalk returns the walk and the scan root's slash path relative to the repository root.
func newGitPkgsWalk(scanRoot string, readParentRules bool, logger *zerolog.Logger) (*gitPkgsWalk, string) {
	w := &gitPkgsWalk{
		root:     scanRoot,
		sections: []DotSnykExcludeSectionName{DotSnykExcludeCode, DotSnykExcludeGlobal},
		logger:   logger,
	}

	repo, err := readGitPkgsRepository(scanRoot)
	if err != nil {
		logger.Debug().Msgf("no git repository above %s: %v", scanRoot, err)
	} else {
		w.root = repo.root
		w.tracked = repo.tracked
	}

	rel := gitPkgsRelative(w.root, scanRoot)

	// Layers are pushed from lowest to highest priority, matching git's precedence.
	w.git.push(gitPkgsGlobalExcludes(scanRoot, logger))
	if repo != nil {
		w.git.push(gitPkgsRulesFromFile(filepath.Join(w.root, ".git", "info", "exclude"), "", logger))
	}
	if readParentRules {
		for folder := range gitPkgsAncestors(rel) {
			w.git.push(gitPkgsRulesFromFile(filepath.Join(w.root, filepath.FromSlash(folder), ".gitignore"), folder, logger))
		}
	}

	return w, rel
}

// gitPkgsAncestors yields the repository root and each folder above rel, as slash paths.
func gitPkgsAncestors(rel string) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		if rel == "" {
			return
		}
		if !yield("") {
			return
		}
		for i := 0; i < len(rel); i++ {
			if rel[i] == '/' && !yield(rel[:i]) {
				return
			}
		}
	}
}

type gitPkgsRepository struct {
	root    string
	tracked map[string]bool
}

// readGitPkgsRepository opens the repository above scanRoot and reads its index.
func readGitPkgsRepository(scanRoot string) (*gitPkgsRepository, error) {
	repo, err := git.PlainOpenWithOptions(scanRoot, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, err
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return nil, err
	}

	root, err := matchingRepositoryRoot(scanRoot, worktree.Filesystem.Root())
	if err != nil {
		return nil, err
	}

	index, err := repo.Storer.Index()
	if err != nil {
		return nil, err
	}

	tracked := make(map[string]bool, len(index.Entries))
	for _, entry := range index.Entries {
		for p := entry.Name; p != "." && p != ""; p = path.Dir(p) {
			tracked[p] = true
		}
	}

	return &gitPkgsRepository{root: root, tracked: tracked}, nil
}

// gitPkgsGlobalExcludes reads core.excludesFile through the git binary, because go-git does not
// honor GIT_CONFIG_GLOBAL. A missing setting exits non-zero, which means no rules.
func gitPkgsGlobalExcludes(dir string, logger *zerolog.Logger) *gitignore.Matcher {
	out, err := exec.Command("git", "-C", dir, "config", "--path", "--get", "core.excludesFile").Output()
	if err != nil {
		return nil
	}

	excludesFile := strings.TrimSpace(string(out))
	if excludesFile == "" {
		return nil
	}

	return gitPkgsRulesFromFile(excludesFile, "", logger)
}

// gitPkgsRelative returns dir as a slash path below root. Both are absolute, in the same spelling.
func gitPkgsRelative(root, dir string) string {
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." {
		return ""
	}

	return filepath.ToSlash(rel)
}

// gitPkgsChild joins a folder's root-relative path and an entry name with one allocation. A folder
// gets a trailing slash because the matcher reads that as "is a directory".
func gitPkgsChild(rel, name string, isDir bool) string {
	switch {
	case rel == "" && !isDir:
		return name
	case rel == "":
		return name + "/"
	case !isDir:
		return rel + "/" + name
	default:
		return rel + "/" + name + "/"
	}
}

// walk lists one folder. rel is the folder's slash path from the repository root.
func (w *gitPkgsWalk) walk(dir, rel string, dirIgnored bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		w.logger.Warn().Err(err).Msgf("skipping unreadable folder %s", dir)
		return
	}

	gitRules, snykRules := w.readFolderRules(dir, rel, entries, !dirIgnored)
	w.snyk.push(snykRules)
	defer w.snyk.pop()
	w.git.push(gitRules)
	defer w.git.pop()

	w.addFiles(dir, rel, entries, dirIgnored)
	w.descend(dir, rel, entries, dirIgnored)
}

// addFiles emits the files of one folder that survive the rules.
func (w *gitPkgsWalk) addFiles(dir, rel string, entries []fs.DirEntry, dirIgnored bool) {
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 || name == ".git" {
			continue
		}

		child := gitPkgsChild(rel, name, false)
		if w.snyk.excludes(child) {
			continue
		}
		if w.tracked[child] || (!dirIgnored && !w.git.excludes(child)) {
			w.files = append(w.files, filepath.Join(dir, name))
		}
	}
}

// descend walks the subfolders of one folder, skipping ignored ones unless they hold tracked files.
func (w *gitPkgsWalk) descend(dir, rel string, entries []fs.DirEntry, dirIgnored bool) {
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || name == ".git" {
			continue
		}

		child := gitPkgsChild(rel, name, true)
		if w.snyk.excludes(child) {
			continue
		}

		// Computed before the tracked check: a tracked folder is entered even when git ignores it, and
		// its untracked files are then dropped by dirIgnored.
		subIgnored := w.git.excludes(child)
		childRel := child[:len(child)-1]
		if w.tracked[childRel] || (!dirIgnored && !subIgnored) {
			w.walk(filepath.Join(dir, name), childRel, dirIgnored || subIgnored)
		}
	}
}

// readFolderRules reads the rule files that sit directly in dir. .gitignore is read only when the
// folder is not git-ignored, as git does. A folder without rule files gets nil matchers.
func (w *gitPkgsWalk) readFolderRules(dir, rel string, entries []fs.DirEntry, readGitIgnore bool) (gitRules, snykRules *gitignore.Matcher) {
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}

		file := filepath.Join(dir, entry.Name())
		switch entry.Name() {
		case ".gitignore":
			if readGitIgnore {
				gitRules = gitPkgsRulesFromFile(file, rel, w.logger)
			}
		case ".dcignore":
			content, err := os.ReadFile(file)
			if err != nil {
				w.logger.Warn().Err(err).Msgf("cannot read %s", file)
				continue
			}
			snykRules = addGitPkgsRules(snykRules, rel, content)
		case ".snyk":
			content, err := os.ReadFile(file)
			if err != nil {
				w.logger.Warn().Err(err).Msgf("cannot read %s", file)
				continue
			}
			snykRules = addGitPkgsRules(snykRules, rel, gitPkgsSnykPaths(content, w.sections, w.logger))
		}
	}

	return gitRules, snykRules
}

// addGitPkgsRules adds content to m, creating it on first use, so a folder holds one snyk matcher
// however many rule files it has.
func addGitPkgsRules(m *gitignore.Matcher, folder string, content []byte) *gitignore.Matcher {
	if m == nil {
		m = gitignore.New("")
	}
	m.AddPatterns(content, folder)

	return m
}
