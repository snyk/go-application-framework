package utils

import "path"

func SnykCacheDir() (string, error) {
	osutil := NewSnykOSUtil()
	return SnykCacheDirImpl(osutil)
}

func SnykCacheDirImpl(osUtil SnykOSUtil) (string, error) {
	baseDirectory, err := osUtil.UserCacheDir()
	if err != nil {
		// Returning "snyk" to be used as the cache directory name later.
		return "snyk", err
	}

	snykCacheDir := path.Join(baseDirectory, "snyk")
	err = osUtil.MkdirAll(snykCacheDir, FILEPERM_755)
	if err != nil {
		// Returning "snyk" to be used as the cache directory name later.
		return "snyk", err
	}

	return snykCacheDir, nil
}

func FullPathInSnykCacheDir(cacheDir string, filename string) (string, error) {
	return path.Join(cacheDir, filename), nil
}
