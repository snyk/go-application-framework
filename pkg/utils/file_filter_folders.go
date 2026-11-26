package utils

import (
	"path/filepath"
	"strings"
	"sync"
)

type excludedFolder struct {
	byAll   bool
	byOther bool
}

// folderExclusions memoizes which folders below root the rules exclude, so each folder is matched
// once, however many of its files the filter workers test concurrently. The folders of a file are the
// prefixes of its slash path that end before a "/", which is what the rules see when they match the
// path as a string, also for paths that are not clean.
type folderExclusions struct {
	predicate  *exclusionPredicate
	rootPrefix string
	mu         sync.Mutex
	folders    map[string]*folderExclusion
}

type folderExclusion struct {
	once   sync.Once
	folder excludedFolder
}

func (fw *FileFilter) newFolderExclusions(rules []string) *folderExclusions {
	return &folderExclusions{
		predicate:  fw.newExclusionPredicate(rules),
		rootPrefix: folderRootPrefix(fw.path),
		folders:    map[string]*folderExclusion{},
	}
}

// folderRootPrefix returns the slash path that the paths below root start with.
func folderRootPrefix(root string) string {
	slashRoot := filepath.ToSlash(filepath.Clean(root))
	switch {
	case slashRoot == ".":
		return ""
	case strings.HasSuffix(slashRoot, "/"):
		return slashRoot
	default:
		return slashRoot + "/"
	}
}

// parentFolder returns the folder of slashPath, or false when slashPath is not inside a folder below root.
func (e *folderExclusions) parentFolder(slashPath string) (string, bool) {
	rest, ok := strings.CutPrefix(slashPath, e.rootPrefix)
	if !ok {
		return "", false
	}
	i := strings.LastIndexByte(rest, '/')
	if i <= 0 {
		return "", false
	}
	return slashPath[:len(e.rootPrefix)+i], true
}

func (e *folderExclusions) excludedByFolder(file string) bool {
	dir, ok := e.parentFolder(filepath.ToSlash(file))
	if !ok {
		return false
	}
	return e.predicate.excludedByFolder(file, e.of(dir))
}

func (e *folderExclusions) isExcluded(file string) bool {
	return e.excludedByFolder(file) || e.predicate.isExcluded(file)
}

func (e *folderExclusions) of(slashDir string) excludedFolder {
	e.mu.Lock()
	exclusion, ok := e.folders[slashDir]
	if !ok {
		exclusion = &folderExclusion{}
		e.folders[slashDir] = exclusion
	}
	e.mu.Unlock()

	exclusion.once.Do(func() {
		var parent excludedFolder
		if parentDir, ok := e.parentFolder(slashDir); ok {
			parent = e.of(parentDir)
		}
		exclusion.folder = e.predicate.folderState(slashDir, parent)
	})
	return exclusion.folder
}

const folderLookahead = 1024

// matchAhead forwards files and has up to workers goroutines match the folder of each file as soon as
// its first file is read. The file stream reaches the filter workers one folder at a time, so without a
// lookahead they all wait on the same folder. A folder is not queued while the lookahead is full; the
// filter worker that needs it matches it instead. Every goroutine is registered in matching before
// matchAhead returns.
func (e *folderExclusions) matchAhead(files <-chan string, workers int64, matching *sync.WaitGroup) <-chan string {
	ahead := make(chan string, folderLookahead)
	dirs := make(chan string, folderLookahead)
	for range workers {
		matching.Add(1)
		go func() {
			defer matching.Done()
			for dir := range dirs {
				e.of(dir)
			}
		}()
	}
	matching.Add(1)
	go func() {
		defer matching.Done()
		defer close(ahead)
		defer close(dirs)
		seen := map[string]struct{}{}
		for file := range files {
			if dir, ok := e.parentFolder(filepath.ToSlash(file)); ok {
				if _, isSeen := seen[dir]; !isSeen {
					seen[dir] = struct{}{}
					select {
					case dirs <- dir:
					default:
					}
				}
			}
			ahead <- file
		}
	}()
	return ahead
}
