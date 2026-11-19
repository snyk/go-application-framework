package utils

import (
	"path"
)

func SnykCacheDir() (string, error) {
	osutil := NewSnykOSUtil()
	return SnykCacheDirImpl(osutil)
}

func SnykCacheDirImpl(osUtil SnykOSUtil) (string, error) {
	var snykCacheDir string
	subDir := path.Join("snyk", "snyk-cli")
	baseDirectory, err := osUtil.UserCacheDir()

	// list of possible directories used as cache directory. An empty base, for example without a home directory, is
	// skipped: the relative subDir would be in the working directory (CLI-1124).
	possibleCacheDirectories := []string{}
	if baseDirectory != "" {
		possibleCacheDirectories = append(possibleCacheDirectories, path.Join(baseDirectory, subDir))
	}
	possibleCacheDirectories = append(possibleCacheDirectories, path.Join(osUtil.TempDir(), subDir))

	for _, snykCacheDir = range possibleCacheDirectories {
		mkdirErr := osUtil.MkdirAll(snykCacheDir, FILEPERM_755)
		if mkdirErr != nil {
			err = mkdirErr
			continue
		}
		break
	}

	return snykCacheDir, err
}

func FullPathInSnykCacheDir(cacheDir string, filename string) (string, error) {
	return path.Join(cacheDir, filename), nil
}
