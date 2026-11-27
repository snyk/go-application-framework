package utils

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
)

type excludedFolder struct {
	byAll   bool
	byOther bool
	linked  string // the topmost folder, from the folder itself up to root, that is a symlink, or empty; a slash path
}

// folderExclusions memoizes which folders below root the rules exclude, so each folder is matched once,
// however many of its files the filter workers test concurrently. With FF_FILE_FILTER_GIT_SEMANTICS, a file
// inside an excluded folder is excluded, as in git. The folders of a file are the prefixes of its slash path
// that end before a "/", which is what the rules see when they match the path as a string, also for paths
// that are not clean.
type folderExclusions struct {
	predicate  *exclusionPredicate
	rootPrefix string
	filter     *FileFilter
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
		filter:     fw,
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

// escapesRelativeRoot reports whether slashPath leaves a root that is ".", which has no prefix to tell
// paths inside from outside. Cleaning first catches unclean paths such as "a/../../x". The leading "/" check
// covers rooted paths without a drive, which filepath.IsAbs does not report on Windows.
func escapesRelativeRoot(slashPath string) bool {
	cleaned := path.Clean(slashPath)
	return cleaned == ".." ||
		strings.HasPrefix(cleaned, "../") ||
		strings.HasPrefix(slashPath, "/") ||
		filepath.IsAbs(filepath.FromSlash(slashPath))
}

// parentFolder returns the folder of slashPath, or false when slashPath is not inside a folder below root.
func (e *folderExclusions) parentFolder(slashPath string) (string, bool) {
	rest, ok := strings.CutPrefix(slashPath, e.rootPrefix)
	if !ok || (e.rootPrefix == "" && escapesRelativeRoot(slashPath)) {
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
	folder := e.of(dir)
	if folder.linked != "" {
		// Reported here, not where the folder is memoized, so the handler never runs inside a sync.Once that
		// other workers wait on. One report for the topmost symlinked folder stands for every file below it.
		e.filter.reportSkippedSymlink(filepath.FromSlash(folder.linked))
		return true
	}
	return e.predicate.excludedByFolder(file, folder)
}

func (e *folderExclusions) isExcluded(file string) bool {
	if e.predicate.gitSemantics && inGitFolder(filepath.ToSlash(file)) {
		return true
	}
	if e.excludedByFolder(file) || e.predicate.isExcluded(file) {
		return true
	}
	if !isSymlink(file) {
		return false
	}
	e.filter.reportSkippedSymlink(file)
	return true
}

// inGitFolder reports whether a path element of slashPath is .git.
func inGitFolder(slashPath string) bool {
	return slashPath == gitFolderName ||
		strings.HasPrefix(slashPath, gitFolderName+"/") ||
		strings.HasSuffix(slashPath, "/"+gitFolderName) ||
		strings.Contains(slashPath, "/"+gitFolderName+"/")
}

// isSymlink covers callers that pass their own file channel, since GetAllFiles never returns symlinks. A path
// that cannot be stat'ed is not reported as a symlink.
func isSymlink(file string) bool {
	info, err := os.Lstat(file)
	return err == nil && info.Mode()&fs.ModeSymlink != 0
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
		exclusion.folder.linked = parent.linked
		if parent.linked == "" && isSymlink(filepath.FromSlash(slashDir)) {
			exclusion.folder.linked = slashDir
		}
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
