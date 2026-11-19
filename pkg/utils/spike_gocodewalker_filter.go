package utils

import (
	"bytes"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/boyter/gocodewalker"
	rulematcher "github.com/boyter/gocodewalker/go-gitignore"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
)

const (
	gocodewalkerGitDir       = ".git"
	gocodewalkerDcignoreFile = ".dcignore"
	gocodewalkerSnykFile     = ".snyk"
)

// gocodewalkerScan returns the absolute paths of the files that survive filtering under scanRoot,
// walking with gocodewalker and adding what the library cannot express: tracked files inside
// ignored folders, .snyk and .dcignore exclusions, and the removal of symlinks and .git entries.
func gocodewalkerScan(scanRoot string, logger *zerolog.Logger) []string {
	absRoot, err := filepath.Abs(scanRoot)
	if err != nil {
		return nil
	}

	walked := gocodewalkerWalk(absRoot, logger)
	tracked := readGocodewalkerTrackedFiles(absRoot, logger)

	// A tracked file inside an ignored folder is never listed by the walk, so it comes from the index.
	// The index can also name files that are gone from disk, hence the lstat.
	seen := make(map[string]struct{}, len(walked))
	for _, p := range walked {
		seen[gocodewalkerRelative(absRoot, p)] = struct{}{}
	}
	var extras []string
	for rel := range tracked {
		if _, ok := seen[rel]; ok {
			continue
		}
		full := filepath.Join(absRoot, filepath.FromSlash(rel))
		if info, err := os.Lstat(full); err == nil && info.Mode().IsRegular() {
			extras = append(extras, full)
		}
	}

	rules := newGocodewalkerSnykRules(absRoot, logger)
	rules.discoverFromFiles(walked)
	rules.discoverFromExtras(extras)

	files := make([]string, 0, len(walked)+len(extras))
	for _, p := range append(walked, extras...) {
		if !rules.excludes(gocodewalkerRelative(absRoot, p)) {
			files = append(files, p)
		}
	}

	return files
}

// gocodewalkerWalk lists the regular files the library keeps under absRoot.
func gocodewalkerWalk(absRoot string, logger *zerolog.Logger) []string {
	queue := make(chan *gocodewalker.File, 1024)
	walker := gocodewalker.NewFileWalker(absRoot, queue)
	// Hidden entries are walked: .gitignore, .snyk, .dcignore and folders such as .github are dot entries,
	// and git has no hidden-file rule.
	walker.IncludeHidden = true
	// Neither .ignore nor .gitmodules is a rule file for GAF, and submodules are plain folders.
	walker.IgnoreIgnoreFile = true
	walker.IgnoreGitModules = true
	walker.ExcludeDirectory = []string{gocodewalkerGitDir}
	walker.SetErrorHandler(func(err error) bool {
		logger.Warn().Err(err).Msg("gocodewalker skipped an entry")
		return true
	})

	go func() {
		if err := walker.Start(); err != nil {
			logger.Warn().Err(err).Msg("gocodewalker stopped early")
		}
	}()

	var files []string
	for f := range queue {
		// The library reports every non-directory entry, symlinks included, and a .git file marks a submodule.
		if f.Filename == gocodewalkerGitDir {
			continue
		}
		if info, err := os.Lstat(f.Location); err != nil || !info.Mode().IsRegular() {
			continue
		}
		files = append(files, f.Location)
	}

	return files
}

// readGocodewalkerTrackedFiles returns the regular files in the git index under absRoot, as
// slash paths relative to absRoot. It returns nil outside a repository.
func readGocodewalkerTrackedFiles(absRoot string, logger *zerolog.Logger) map[string]struct{} {
	repo, err := git.PlainOpenWithOptions(absRoot, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		logger.Debug().Msgf("no git repository above %s: %v", absRoot, err)
		return nil
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return nil
	}
	repoRoot, err := matchingRepositoryRoot(absRoot, worktree.Filesystem.Root())
	if err != nil {
		return nil
	}
	rel, err := filepath.Rel(repoRoot, absRoot)
	if err != nil {
		return nil
	}
	prefix := ""
	if rel != "." {
		prefix = filepath.ToSlash(rel) + "/"
	}

	index, err := repo.Storer.Index()
	if err != nil {
		return nil
	}

	tracked := make(map[string]struct{}, len(index.Entries))
	for _, entry := range index.Entries {
		if entry.Mode != filemode.Regular && entry.Mode != filemode.Executable && entry.Mode != filemode.Deprecated {
			continue
		}
		if under, ok := strings.CutPrefix(entry.Name, prefix); ok {
			tracked[under] = struct{}{}
		}
	}

	return tracked
}

// gocodewalkerRelative returns a path below absRoot as a slash path relative to it.
func gocodewalkerRelative(absRoot, full string) string {
	return filepath.ToSlash(strings.TrimPrefix(full, absRoot+string(filepath.Separator)))
}

// gocodewalkerSnykRules applies .dcignore and .snyk files to a finished file list. The library can
// read a .dcignore itself, but never inside a folder it skips, and it cannot read .snyk at all.
// Rule files are found from the list itself and from the folders of tracked files that the library skipped.
type gocodewalkerSnykRules struct {
	absRoot string
	logger  *zerolog.Logger
	// byDir holds the rule sets of the .dcignore and .snyk in each folder (relative slash path, "" for the
	// scan root), in file name order so a later set wins.
	byDir map[string][]rulematcher.GitIgnore
	// probed records the folders already searched for rule files.
	probed      map[string]struct{}
	dirExcluded map[string]bool
}

func newGocodewalkerSnykRules(absRoot string, logger *zerolog.Logger) *gocodewalkerSnykRules {
	return &gocodewalkerSnykRules{
		absRoot:     absRoot,
		logger:      logger,
		byDir:       map[string][]rulematcher.GitIgnore{},
		probed:      map[string]struct{}{},
		dirExcluded: map[string]bool{},
	}
}

func (r *gocodewalkerSnykRules) discoverFromFiles(files []string) {
	for _, full := range files {
		name := filepath.Base(full)
		if name != gocodewalkerDcignoreFile && name != gocodewalkerSnykFile {
			continue
		}
		dir := path.Dir(gocodewalkerRelative(r.absRoot, full))
		if dir == "." {
			dir = ""
		}
		r.probe(dir)
	}
}

// discoverFromExtras probes every folder from a skipped tracked file up to the scan root, because the
// library never listed the rule files that sit next to them.
func (r *gocodewalkerSnykRules) discoverFromExtras(extras []string) {
	for _, full := range extras {
		for dir := path.Dir(gocodewalkerRelative(r.absRoot, full)); ; dir = path.Dir(dir) {
			if dir == "." {
				dir = ""
			}
			r.probe(dir)
			if dir == "" {
				break
			}
		}
	}
}

// probe reads the rule files of one folder once.
func (r *gocodewalkerSnykRules) probe(dir string) {
	if _, ok := r.probed[dir]; ok {
		return
	}
	r.probed[dir] = struct{}{}

	folder := filepath.Join(r.absRoot, filepath.FromSlash(dir))
	if content, err := os.ReadFile(filepath.Join(folder, gocodewalkerDcignoreFile)); err == nil {
		r.byDir[dir] = append(r.byDir[dir], rulematcher.New(bytes.NewReader(content), folder, nil))
	}
	if content, err := os.ReadFile(filepath.Join(folder, gocodewalkerSnykFile)); err == nil {
		lines := gocodewalkerSnykExcludeLines(content, r.logger)
		r.byDir[dir] = append(r.byDir[dir], rulematcher.New(strings.NewReader(strings.Join(lines, "\n")), folder, nil))
	}
}

// excludes reports whether the file, or any folder above it, is excluded. Each rule file applies
// to its own folder and below, and the deepest matching rule decides.
func (r *gocodewalkerSnykRules) excludes(rel string) bool {
	if len(r.byDir) == 0 {
		return false
	}

	dir := path.Dir(rel)
	if dir == "." {
		dir = ""
	}

	return r.folderExcluded(dir) || r.decide(dir, rel, false)
}

func (r *gocodewalkerSnykRules) folderExcluded(dir string) bool {
	if dir == "" {
		return false
	}
	if excluded, ok := r.dirExcluded[dir]; ok {
		return excluded
	}

	parent := path.Dir(dir)
	if parent == "." {
		parent = ""
	}
	excluded := r.folderExcluded(parent) || r.decide(parent, dir, true)
	r.dirExcluded[dir] = excluded

	return excluded
}

// decide asks the rule sets of dir and each folder above it, deepest first, about rel.
func (r *gocodewalkerSnykRules) decide(dir, rel string, isDir bool) bool {
	for {
		sets := r.byDir[dir]
		relToSet := rel
		if dir != "" {
			relToSet = strings.TrimPrefix(rel, dir+"/")
		}
		for i := len(sets) - 1; i >= 0; i-- {
			if match := sets[i].Relative(relToSet, isDir); match != nil {
				return match.Ignore()
			}
		}

		if dir == "" {
			return false
		}
		dir = path.Dir(dir)
		if dir == "." {
			dir = ""
		}
	}
}

// gocodewalkerSnykExcludeLines returns the exclude paths of the code and global sections of a .snyk
// file as ignore-file lines. Expired and absolute entries are skipped, as the current parser does.
func gocodewalkerSnykExcludeLines(content []byte, logger *zerolog.Logger) []string {
	var file DotSnykRule
	if err := yaml.Unmarshal(content, &file); err != nil {
		logger.Error().Msgf("parse .snyk failed: %v", err)
		return nil
	}

	var lines []string
	for _, section := range []DotSnykExcludeSectionName{DotSnykExcludeCode, DotSnykExcludeGlobal} {
		node, ok := file.Exclude[section]
		if !ok {
			continue
		}

		var entries []dotSnykExclude
		if err := node.Decode(&entries); err != nil {
			logger.Error().Msgf("parse .snyk section %q failed: %v", section, err)
			continue
		}

		for _, entry := range entries {
			if expired, _ := entry.IsExpired(); expired {
				continue
			}
			if filepath.IsAbs(entry.Path) {
				logger.Warn().Msgf("Absolute paths are currently not supported when excluding files (%s)", entry.Path)
				continue
			}
			lines = append(lines, entry.Path)
		}
	}

	return lines
}
