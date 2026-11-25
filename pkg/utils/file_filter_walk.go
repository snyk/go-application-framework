package utils

import (
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"
)

type excludedFolder struct {
	byAll   bool
	byOther bool
}

func WithRuleFiles(ruleFiles []string) FileFilterOption {
	return func(filter *FileFilter) error {
		filter.ruleFiles = ruleFiles
		return nil
	}
}

func WithExtraRules(rules []string) FileFilterOption {
	return func(filter *FileFilter) error {
		filter.extraRules = rules
		return nil
	}
}

// WalkFilteredFiles returns the same files as GetFilteredFiles(GetAllFiles(), rules), where rules are
// the extra rules followed by GetRules(ruleFiles). Excluded folders are still read, because their
// ignore files count and an unreadable entry ends the walk as in GetAllFiles, but their files are
// only tested against the negated rules.
func (fw *FileFilter) WalkFilteredFiles() (chan string, error) {
	rules, err := fw.GetRules(fw.ruleFiles)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	folders := fw.newFolderExclusions(slices.Concat(fw.extraRules, rules))
	folders.matchFolders(fw.max_threads)

	filtered := make(chan string)
	go func() {
		defer close(filtered)
		fw.filterFiles(fw.GetAllFiles(), folders.isExcluded, filtered, start)
	}()

	return filtered, nil
}

// folderExclusions memoizes which folders below root the rules exclude, so each folder is matched
// once, however many of its files the filter workers test concurrently.
type folderExclusions struct {
	predicate *exclusionPredicate
	root      string
	mu        sync.Mutex
	folders   map[string]*folderExclusion
}

type folderExclusion struct {
	once   sync.Once
	folder excludedFolder
}

func (fw *FileFilter) newFolderExclusions(rules []string) *folderExclusions {
	return &folderExclusions{
		predicate: fw.newExclusionPredicate(rules),
		root:      filepath.Clean(fw.path),
		folders:   map[string]*folderExclusion{},
	}
}

func (e *folderExclusions) excludedByFolder(file string) bool {
	return e.predicate.excludedByFolder(file, e.of(filepath.Dir(file)))
}

func (e *folderExclusions) isExcluded(file string) bool {
	return e.excludedByFolder(file) || e.predicate.isExcluded(file)
}

func (e *folderExclusions) of(dir string) excludedFolder {
	if dir == e.root || dir == filepath.Dir(dir) {
		return excludedFolder{}
	}

	e.mu.Lock()
	exclusion, ok := e.folders[dir]
	if !ok {
		exclusion = &folderExclusion{}
		e.folders[dir] = exclusion
	}
	e.mu.Unlock()

	exclusion.once.Do(func() {
		exclusion.folder = e.predicate.folderState(dir, e.of(filepath.Dir(dir)))
	})
	return exclusion.folder
}

// matchFolders matches the folders below root ahead of the file stream, which reaches the filter
// workers one folder at a time and would otherwise make them wait on each other's folder.
func (e *folderExclusions) matchFolders(workers int64) {
	folders := make(chan string)
	go func() {
		defer close(folders)
		//nolint:errcheck // a folder left out is matched when its first file is filtered
		filepath.WalkDir(e.root, func(path string, d os.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				folders <- path
			}
			return err
		})
	}()

	for range workers {
		go func() {
			for dir := range folders {
				e.of(dir)
			}
		}()
	}
}
