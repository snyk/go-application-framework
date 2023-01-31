package utils

import (
	"os"
	"path"
)

type SnykCacheDirUtil interface {
	UserCacheDir() (string, error)
	MkdirAll(path string, perm os.FileMode) error
}

type baseDirectory struct{}

func (bd *baseDirectory) UserCacheDir() (string, error) {
	return os.UserCacheDir()
}

func (bd *baseDirectory) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func NewSnykCacheDirUtil() SnykCacheDirUtil {
	return &baseDirectory{}
}

func SnykCacheDir() (string, error) {
	osutil := NewSnykCacheDirUtil()
	return SnykCacheDirImpl(osutil)
}

func SnykCacheDirImpl(osutil SnykCacheDirUtil) (string, error) {
	baseDirectory, err := osutil.UserCacheDir()
	if err != nil {
		// Returning "snyk" to be used as the cache directory name later.
		return "snyk", err
	}

	snykCacheDir := path.Join(baseDirectory, "snyk")
	err = osutil.MkdirAll(snykCacheDir, FILEPERM_755)
	if err != nil {
		// Returning "snyk" to be used as the cache directory name later.
		return "snyk", err
	}

	return snykCacheDir, nil
}

func FullPathInSnykCacheDir(cacheDir string, filename string) (string, error) {
	return path.Join(cacheDir, filename), nil
}
