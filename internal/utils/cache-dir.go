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

	// list of possible directories used as cache directory
	possibleCacheDirectories := []string{
		path.Join(baseDirectory, subDir),
		path.Join(osUtil.TempDir(), subDir),
		subDir,
	}

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
