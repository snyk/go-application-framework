// OS interface wrappers

package utils

import "os"

type SnykOSUtil interface {
	UserCacheDir() (string, error)
	MkdirAll(path string, perm os.FileMode) error
	Stat(name string) (os.FileInfo, error)
	TempDir() string
}

type baseDirectory struct{}

func (bd *baseDirectory) UserCacheDir() (string, error) {
	return os.UserCacheDir()
}

func (bd *baseDirectory) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (bd *baseDirectory) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

func (bd *baseDirectory) TempDir() string {
	return os.TempDir()
}

func NewSnykOSUtil() SnykOSUtil {
	return &baseDirectory{}
}
