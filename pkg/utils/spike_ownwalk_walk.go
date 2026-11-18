package utils

import (
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog"
)

// ownWalk lists the files a scan sends in one pass over the tree.
type ownWalk struct {
	// root is the repository root, or the scan root outside a repository. Every rule path is relative to it.
	root string
	// tracked holds the index entries and each ancestor folder of them, as root-relative slash paths.
	tracked map[string]bool
	// git holds .gitignore rules. Its bottom layers are the base rules: global excludes, info/exclude and
	// parent .gitignore files.
	git ownWalkRuleStack
	// snyk holds .snyk and .dcignore rules. They are a separate stack because git never reads them, and
	// they exclude tracked files too.
	snyk     ownWalkRuleStack
	sections []DotSnykExcludeSectionName
	logger   *zerolog.Logger
	files    []string
}

// ownWalkScan returns the absolute paths of the files that survive filtering under scanRoot.
func ownWalkScan(scanRoot string, readParentRules bool) []string {
	logger := zerolog.Nop()
	absRoot, err := filepath.Abs(scanRoot)
	if err != nil {
		return nil
	}

	w, rel := newOwnWalk(absRoot, readParentRules, &logger)
	w.walk(absRoot, rel, false)

	return w.files
}

// newOwnWalk returns the walk and the scan root's path relative to the repository root.
func newOwnWalk(scanRoot string, readParentRules bool, logger *zerolog.Logger) (*ownWalk, []string) {
	w := &ownWalk{
		root:     scanRoot,
		sections: []DotSnykExcludeSectionName{DotSnykExcludeCode, DotSnykExcludeGlobal},
		logger:   logger,
	}

	repo, err := readOwnWalkRepository(scanRoot)
	if err != nil {
		logger.Debug().Msgf("no git repository above %s: %v", scanRoot, err)
	} else {
		w.root = repo.root
		w.tracked = repo.tracked
	}

	rel := ownWalkRelative(w.root, scanRoot)

	// Layers are pushed from lowest to highest priority, matching git's precedence.
	w.git.push(ownWalkGlobalExcludes(scanRoot, logger))
	if repo != nil {
		w.git.push(ownWalkRulesFromFile(filepath.Join(w.root, ".git", "info", "exclude"), nil, logger))
	}
	if readParentRules {
		for i := range rel {
			folder := rel[:i]
			w.git.push(ownWalkRulesFromFile(filepath.Join(w.root, filepath.Join(folder...), ".gitignore"), folder, logger))
		}
	}

	return w, rel
}

type ownWalkRepository struct {
	root    string
	tracked map[string]bool
}

// readOwnWalkRepository opens the repository above scanRoot and reads its index.
func readOwnWalkRepository(scanRoot string) (*ownWalkRepository, error) {
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

	return &ownWalkRepository{root: root, tracked: tracked}, nil
}

// ownWalkGlobalExcludes reads core.excludesFile through the git binary, because that is the only
// reader that honours GIT_CONFIG_GLOBAL. A missing setting exits non-zero, which means no rules.
func ownWalkGlobalExcludes(dir string, logger *zerolog.Logger) []ownWalkRule {
	out, err := exec.Command("git", "-C", dir, "config", "--path", "--get", "core.excludesFile").Output()
	if err != nil {
		return nil
	}

	excludesFile := strings.TrimSpace(string(out))
	if excludesFile == "" {
		return nil
	}

	return ownWalkRulesFromFile(excludesFile, nil, logger)
}

// ownWalkRulesFromFile returns the rules of one ignore file, or none if it does not exist.
func ownWalkRulesFromFile(file string, folder []string, logger *zerolog.Logger) []ownWalkRule {
	content, err := os.ReadFile(file)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Warn().Err(err).Msgf("cannot read ignore file %s", file)
		}
		return nil
	}

	return ownWalkParseRules(content, folder)
}

// ownWalkRelative returns the components of dir below root. Both are absolute, in the same spelling.
func ownWalkRelative(root, dir string) []string {
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." {
		return nil
	}

	return strings.Split(filepath.ToSlash(rel), "/")
}

// appendRel returns a new slice, so sibling entries never share a backing array.
func appendRel(rel []string, name string) []string {
	return append(rel[:len(rel):len(rel)], name)
}

// walk lists one folder. rel is the folder's path from the repository root.
func (w *ownWalk) walk(dir string, rel []string, dirIgnored bool) {
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

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 || name == ".git" {
			continue
		}

		child := appendRel(rel, name)
		if w.snyk.excludes(child, false) {
			continue
		}
		if w.tracked[strings.Join(child, "/")] || (!dirIgnored && !w.git.excludes(child, false)) {
			w.files = append(w.files, filepath.Join(dir, name))
		}
	}

	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || name == ".git" {
			continue
		}

		child := appendRel(rel, name)
		if w.snyk.excludes(child, true) {
			continue
		}

		// Computed before the tracked check: a tracked folder is entered even when git ignores it, and
		// its untracked files are then dropped by dirIgnored.
		subIgnored := w.git.excludes(child, true)
		if w.tracked[strings.Join(child, "/")] || (!dirIgnored && !subIgnored) {
			w.walk(filepath.Join(dir, name), child, dirIgnored || subIgnored)
		}
	}
}

// readFolderRules reads the rule files that sit directly in dir. .gitignore is read only when the
// folder is not git-ignored, as git does.
func (w *ownWalk) readFolderRules(dir string, rel []string, entries []fs.DirEntry, readGitIgnore bool) (gitRules, snykRules []ownWalkRule) {
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}

		file := filepath.Join(dir, entry.Name())
		switch entry.Name() {
		case ".gitignore":
			if readGitIgnore {
				gitRules = ownWalkRulesFromFile(file, rel, w.logger)
			}
		case ".dcignore":
			snykRules = append(snykRules, ownWalkRulesFromFile(file, rel, w.logger)...)
		case ".snyk":
			content, err := os.ReadFile(file)
			if err != nil {
				w.logger.Warn().Err(err).Msgf("cannot read %s", file)
				continue
			}
			snykRules = append(snykRules, ownWalkSnykRules(content, rel, w.sections, w.logger)...)
		}
	}

	return gitRules, snykRules
}
