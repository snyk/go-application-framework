package utils

import (
	"path/filepath"
	"slices"
	"sync"
	"time"
)

type excludedFolder struct {
	byAll   bool
	byOther bool
}

// WithRuleFiles sets the ignore file names, such as .gitignore, .dcignore and .snyk, whose rules
// WalkFilteredFiles applies. Only WalkFilteredFiles reads them.
func WithRuleFiles(ruleFiles []string) FileFilterOption {
	return func(filter *FileFilter) error {
		filter.ruleFiles = ruleFiles
		return nil
	}
}

// WithExtraRules sets glob rules from the caller that WalkFilteredFiles applies before the rules from
// the rule files. Only WalkFilteredFiles reads them.
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

	filtered := make(chan string)
	go func() {
		defer close(filtered)
		var matching sync.WaitGroup
		defer matching.Wait()
		fw.filterFiles(folders.matchAhead(fw.GetAllFiles(), &matching), folders.isExcluded, filtered, start)
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

const folderLookahead = 1024

// matchAhead forwards files and starts matching the folder of each one when its first file is read.
// The file stream reaches the filter workers one folder at a time, so without a lookahead they all
// wait on the same folder. Every matching goroutine is registered in matching before the returned
// channel is closed.
func (e *folderExclusions) matchAhead(files <-chan string, matching *sync.WaitGroup) <-chan string {
	ahead := make(chan string, folderLookahead)
	go func() {
		defer close(ahead)
		seen := map[string]struct{}{}
		for file := range files {
			dir := filepath.Dir(file)
			if _, ok := seen[dir]; !ok {
				seen[dir] = struct{}{}
				matching.Add(1)
				go func() {
					defer matching.Done()
					e.of(dir)
				}()
			}
			ahead <- file
		}
	}()
	return ahead
}
