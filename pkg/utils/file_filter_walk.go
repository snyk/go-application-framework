package utils

import (
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	gitignore "github.com/sabhiram/go-gitignore"
)

type directoryMatchers struct {
	nonGitignore *gitignore.GitIgnore
	all          *gitignore.GitIgnore
}

type ruleWalker struct {
	filter              *FileFilter
	ruleFiles           []string
	respectTrackedFiles bool
	globs               []string
	hasNegation         bool
	matchers            []directoryMatchers
	trackedDirs         map[string]struct{}
	trackedDirsLoaded   bool
	trackedRepoRoot     string
	excludedDirs        map[string]struct{}
}

type WalkFilteredFilesOption func(*walkConfig)

type walkConfig struct {
	extraRules []string
}

func WithExtraRules(rules []string) WalkFilteredFilesOption {
	return func(config *walkConfig) {
		config.extraRules = rules
	}
}

func (fw *FileFilter) WalkFilteredFiles(ruleFiles []string, options ...WalkFilteredFilesOption) (chan string, error) {
	files, rules, err := fw.discoverFiles(ruleFiles, options...)
	if err != nil {
		return nil, err
	}

	return fw.GetFilteredFiles(files, rules), nil
}

func (fw *FileFilter) discoverFiles(ruleFiles []string, options ...WalkFilteredFilesOption) (chan string, []string, error) {
	var config walkConfig
	for _, option := range options {
		option(&config)
	}

	walker := newRuleWalker(fw, ruleFiles, config.extraRules)
	foundRules, excludedDirs, err := walker.collect()
	if err != nil {
		return nil, nil, err
	}

	files := make(chan string)
	go func() {
		defer close(files)
		fw.sendFilesSkipping(excludedDirs, files)
	}()

	return files, slices.Concat(config.extraRules, fw.defaultRules, foundRules), nil
}

func (fw *FileFilter) sendFilesSkipping(excludedDirs map[string]struct{}, files chan<- string) {
	if !isDirectory(fw.path) {
		files <- fw.path
		return
	}
	fw.sendDirFilesSkipping(fw.path, excludedDirs, files)
}

func (fw *FileFilter) sendDirFilesSkipping(dir string, excludedDirs map[string]struct{}, files chan<- string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fw.logger.Error().Msgf("walk dir failed: %v", err)
		return
	}

	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if !entry.IsDir() {
			files <- path
			continue
		}

		if _, excluded := excludedDirs[path]; !excluded {
			fw.sendDirFilesSkipping(path, excludedDirs, files)
		}
	}
}

func isDirectory(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.IsDir()
}

func newRuleWalker(filter *FileFilter, ruleFiles []string, extraRules []string) *ruleWalker {
	w := &ruleWalker{
		filter:              filter,
		ruleFiles:           ruleFiles,
		respectTrackedFiles: filter.config.GetBool(FF_GITIGNORE_RESPECT_TRACKED_FILES),
		excludedDirs:        map[string]struct{}{},
	}
	w.hasNegation = slices.ContainsFunc(extraRules, isNegation)
	w.addMatchers(extraRules)
	w.addMatchers(filter.defaultRules)
	return w
}

func (w *ruleWalker) collect() ([]string, map[string]struct{}, error) {
	if !isDirectory(w.filter.path) {
		return nil, w.excludedDirs, nil
	}

	err := w.walk(w.filter.path)
	return w.globs, w.excludedDirs, err
}

func (w *ruleWalker) walk(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		w.filter.logger.Error().Msgf("walk dir failed: %v", err)
		return nil
	}

	defer w.restoreScope(len(w.matchers), w.hasNegation)

	err = w.addRulesOf(dir, entries)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		subDir := filepath.Join(dir, entry.Name())
		if w.isExcluded(subDir) {
			w.excludedDirs[subDir] = struct{}{}
			continue
		}

		err = w.walk(subDir)
		if err != nil {
			return err
		}
	}

	return nil
}

func (w *ruleWalker) restoreScope(matcherCount int, hadNegation bool) {
	clear(w.matchers[matcherCount:])
	w.matchers = w.matchers[:matcherCount]
	w.hasNegation = hadNegation
}

func (w *ruleWalker) addRulesOf(dir string, entries []os.DirEntry) error {
	var ignoreFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && slices.Contains(w.ruleFiles, entry.Name()) {
			ignoreFiles = append(ignoreFiles, filepath.Join(dir, entry.Name()))
		}
	}

	globs, err := w.filter.buildGlobs(ignoreFiles)
	if err != nil {
		return err
	}
	if len(globs) == 0 {
		return nil
	}

	w.globs = append(w.globs, globs...)
	w.addMatchers(globs)
	w.hasNegation = w.hasNegation || slices.ContainsFunc(globs, isNegation)
	return nil
}

func isNegation(glob string) bool {
	return strings.HasPrefix(strings.TrimPrefix(glob, gitIgnoreGlobPrefix), "!")
}

func (w *ruleWalker) isExcluded(dir string) bool {
	if w.hasNegation {
		return false
	}

	for _, matchers := range w.matchers {
		if matchers.nonGitignore.MatchesPath(dir) {
			return true
		}

		if w.respectTrackedFiles && matchers.all.MatchesPath(dir) && !w.containsTrackedFiles(dir) {
			return true
		}
	}

	return false
}

func (w *ruleWalker) addMatchers(rules []string) {
	nonGitignore := gitignore.CompileIgnoreLines(rules...)
	all := nonGitignore
	if w.respectTrackedFiles {
		all = gitignore.CompileIgnoreLines(withoutGitignorePrefix(rules)...)
	}

	w.matchers = append(w.matchers, directoryMatchers{nonGitignore: nonGitignore, all: all})
}

func withoutGitignorePrefix(rules []string) []string {
	stripped := make([]string, len(rules))
	for i, rule := range rules {
		stripped[i] = strings.TrimPrefix(rule, gitIgnoreGlobPrefix)
	}
	return stripped
}

func (w *ruleWalker) containsTrackedFiles(dir string) bool {
	if !w.trackedDirsLoaded {
		w.loadTrackedDirs()
	}
	if w.trackedDirs == nil {
		return false
	}

	relativeDir, err := filepath.Rel(w.trackedRepoRoot, dir)
	if err != nil {
		return true
	}

	_, tracked := w.trackedDirs[filepath.ToSlash(relativeDir)]
	return tracked
}

func (w *ruleWalker) loadTrackedDirs() {
	w.trackedDirsLoaded = true

	tracked, ok := w.filter.loadTrackedPaths()
	if !ok {
		return
	}

	w.trackedRepoRoot = tracked.repoRoot
	w.trackedDirs = map[string]struct{}{}
	for file := range tracked.files {
		for dir := path.Dir(file); dir != "." && dir != "/"; dir = path.Dir(dir) {
			if _, known := w.trackedDirs[dir]; known {
				break
			}
			w.trackedDirs[dir] = struct{}{}
		}
	}
}
