package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// IsFileAllowed reports whether the rules allow the file that is the FileFilter's path, without walking any
// folder, for single-file callers such as an editor's file-changed event. It is a point-in-time check, as the
// file may change after the call, and safe for concurrent use.
//
// The rule files named in ruleFiles apply from the file's folder and every folder above it, up to and including
// the folder that contains .git, the boundary; without a .git, up to the filesystem root. Rules nearer to the file
// take precedence; globs come first, as with GetFilteredFiles. WithConfig flags, WithDotSnykSections and the
// default rules apply as in GetRules. FF_GITIGNORE_RESPECT_TRACKED_FILES makes a call with .gitignore rules open
// the repository and read the git index. Without a .git, folders between a rule file and the file are not
// examined, so unlike a directory scan with FF_FILE_FILTER_GIT_SEMANTICS, a negation can re-include a file in a
// folder an outer rule excludes.
//
// Symlinks are never followed. A path that is itself a symlink, also a broken one, returns a *SymlinkError with
// its absolute path. Rule files that are symlinks or not regular files are skipped. The boundary folder, or the
// file's own folder without a .git, and the folders above it may be symlinks, although GetFilteredFiles would
// reject such a root; a symlinked project root that contains .git is a boundary itself, so its files are judged by
// its rules. A file below a symlinked folder below the boundary is not allowed. Skipped symlinks are reported by
// absolute path, once per FileFilter, see WithSkippedPathHandler. The path is made absolute first, resolving ".."
// lexically. It returns an error if the path cannot be stat'ed or is a directory, or if a rule file cannot be read.
func (fw *FileFilter) IsFileAllowed(ruleFiles []string, globs []string) (bool, error) {
	defer fw.flushSkippedSymlinkCount()
	file, err := filepath.Abs(fw.path)
	if err != nil {
		return false, err
	}
	if err = CheckNotSymlink(file); err != nil {
		fw.reportSkippedSymlink(file)
		return false, err
	}
	info, err := os.Lstat(file)
	if err != nil {
		return false, err
	}
	if info.IsDir() {
		return false, fmt.Errorf("%s is a directory, not a file", fw.path)
	}
	root, dirs := ruleFolders(filepath.Dir(file))
	rootIndex, names := slices.Index(dirs, root), slices.Sorted(slices.Values(ruleFiles))
	var ruleFilePaths []string
	for i, dir := range dirs {
		if i > rootIndex && isSymlink(dir) {
			fw.reportSkippedSymlink(dir)
			return false, nil
		}
		for _, name := range names {
			candidate := filepath.Join(dir, name)
			ruleInfo, statErr := os.Lstat(candidate)
			if statErr != nil {
				continue
			}
			switch {
			case ruleInfo.Mode()&os.ModeSymlink != 0:
				fw.reportSkippedSymlink(candidate)
			case ruleInfo.Mode().IsRegular():
				ruleFilePaths = append(ruleFilePaths, candidate)
			}
		}
	}
	fileRules, err := fw.buildGlobs(ruleFilePaths)
	if err != nil {
		return false, err
	}
	return !fw.newFolderExclusions(root, slices.Concat(globs, fw.defaultRules, fileRules)).isExcluded(file), nil
}

// ruleFolders returns the folder that bounds the rules of dir, which is the folder containing .git or dir if there
// is none, and the folders from the outermost one that applies to dir.
func ruleFolders(dir string) (root string, dirs []string) {
	root = dir
	for current := dir; ; current = filepath.Dir(current) {
		dirs = append(dirs, current)
		if _, err := os.Lstat(filepath.Join(current, gitFolderName)); err == nil {
			root = current
			break
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	slices.Reverse(dirs)
	return root, dirs
}
