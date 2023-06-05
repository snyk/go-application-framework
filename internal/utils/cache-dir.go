package utils

import (
	"os"
	"path"
)

func SnykCacheDir() (string, error) {
	osutil := NewSnykOSUtil()
	return SnykCacheDirImpl(osutil)
}

func SnykCacheDirImpl(osUtil SnykOSUtil) (string, error) {
	baseDirectory, err := osUtil.UserCacheDir()
	subDir := path.Join("snyk", "snyk-cli")
	snykCacheDir := path.Join(baseDirectory, subDir)

	err2 := os.MkdirAll(snykCacheDir, FILEPERM_755)
	if err2 != nil {
		// Returning "snyk-cli" to be used as the cache directory name later.
		return subDir, err2
	}

	return snykCacheDir, err
}

func FullPathInSnykCacheDir(cacheDir string, filename string) (string, error) {
	return path.Join(cacheDir, filename), nil
}
