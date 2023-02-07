// OS interface wrappers

package utils

import "os"

type SnykOSUtil interface {
	UserCacheDir() (string, error)
	MkdirAll(path string, perm os.FileMode) error
	Stat(name string) (os.FileInfo, error)
	TempDir() string
}

type snykOsUtilImpl struct{}

func (bd *snykOsUtilImpl) UserCacheDir() (string, error) {
	return os.UserCacheDir()
}

func (bd *snykOsUtilImpl) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (bd *snykOsUtilImpl) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (bd *snykOsUtilImpl) TempDir() string {
	return os.TempDir()
}

func NewSnykOSUtil() SnykOSUtil {
	return &snykOsUtilImpl{}
}
