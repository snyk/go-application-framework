package utils

import (
	"os"
	"path/filepath"
	"slices"
	"time"
)

type excludedFolder struct {
	path    string
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
	predicate := fw.newExclusionPredicate(slices.Concat(fw.extraRules, rules))

	candidates := make(chan string)
	go func() {
		defer close(candidates)
		fw.sendFilesNotExcludedByFolder(predicate, candidates)
	}()

	filtered := make(chan string)
	go func() {
		defer close(filtered)
		fw.filterFiles(candidates, predicate, filtered, start)
	}()

	return filtered, nil
}

// The callback mirrors GetAllFiles, so the walk visits and aborts on exactly the same entries.
func (fw *FileFilter) sendFilesNotExcludedByFolder(predicate *exclusionPredicate, files chan<- string) {
	var folders []excludedFolder
	err := filepath.WalkDir(fw.path, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		parentPath := filepath.Dir(path)
		for len(folders) > 0 && folders[len(folders)-1].path != parentPath {
			folders = folders[:len(folders)-1]
		}
		var parent excludedFolder
		if len(folders) > 0 {
			parent = folders[len(folders)-1]
		}

		if d.IsDir() {
			if path != fw.path {
				folders = append(folders, predicate.folderState(path, parent))
			}
			return nil
		}

		if !predicate.excludedByFolder(path, parent) {
			files <- path
		}
		return nil
	})
	if err != nil {
		fw.logger.Error().Msgf("walk dir failed: %v", err)
	}
}
