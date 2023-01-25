package utils

import (
	"os"
	"path"
)

func SnykCacheDir() (string, error) {
	baseDirectory, err := os.UserCacheDir()
	if err != nil {
		// Returning "snyk" to be used as the cache directory name later.
		return "snyk", err
	}

	snykCacheDir := path.Join(baseDirectory, "snyk")
	err = os.MkdirAll(snykCacheDir, FILEPERM_755)
	if err != nil {
		// Returning "snyk" to be used as the cache directory name later.
		return "snyk", err
	}

	return snykCacheDir, nil
}

func FullPathInSnykCacheDir(cacheDir string, filename string) (string, error) {
	return path.Join(cacheDir, filename), nil
}
