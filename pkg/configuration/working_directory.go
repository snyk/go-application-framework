package configuration

import (
	"os"
	"path/filepath"
)

// configFileExtension is the extension of the configuration files that GAF reads from the configstore.
const configFileExtension = ".json"

// IgnoredWorkingDirConfigFiles reports the configuration files in the current working directory that GAF ignores. For
// each name in files, as given to WithFiles, it checks for a regular file <name>.json directly in the working directory,
// and reports its absolute path when that file is not the file in use. The file in use is pinnedFile when it is not
// empty, and otherwise the configstore file of the same name. Pass the path of WithPinnedFile as pinnedFile.
//
// Only the entry itself is examined, with os.Stat: the contents are never read, the directory is never walked, and a
// symlink counts as the file it points to. A symlink to the file in use is therefore not reported. A directory, a missing
// or dangling entry, and an entry whose status cannot be read are not reported. A name with a path separator is skipped,
// because it does not name a file directly in the working directory. The function does not log or print. The caller
// decides what to show.
func IgnoredWorkingDirConfigFiles(pinnedFile string, files ...string) []string {
	workingDir, err := os.Getwd()
	if err != nil {
		return nil
	}

	var ignored []string
	for _, name := range files {
		// filepath.Base also rejects the empty name
		if filepath.Base(name) != name {
			continue
		}
		candidate := filepath.Join(workingDir, name+configFileExtension)
		if isIgnoredWorkingDirFile(candidate, inUseConfigFile(pinnedFile, name)) {
			ignored = append(ignored, candidate)
		}
	}
	return ignored
}

// inUseConfigFile returns the file that GAF reads for name: the pinned file when there is one, otherwise the configstore
// file. It returns "" when the home directory cannot be determined, because then no configstore file is in use.
func inUseConfigFile(pinnedFile string, name string) string {
	if pinnedFile != "" {
		return pinnedFile
	}
	storeDir, err := basePath()
	if err != nil {
		return ""
	}
	return filepath.Join(storeDir, name+configFileExtension)
}

// isIgnoredWorkingDirFile reports whether candidate is a regular file that is not the file in use. An empty inUse means no
// file is in use.
func isIgnoredWorkingDirFile(candidate string, inUse string) bool {
	info, err := os.Stat(candidate)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	if inUse == "" {
		return true
	}
	inUseInfo, err := os.Stat(inUse)
	if err != nil {
		// the file in use does not exist, so it cannot be the same file
		return true
	}
	return !os.SameFile(info, inUseInfo)
}
