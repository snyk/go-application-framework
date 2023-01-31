package utils

import (
	"errors"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockSnykCacheDirUtil struct {
	cacheDir      string
	cacheDirError error
	dirPath       string
	dirPerm       os.FileMode
	dirError      error
}

func (m *mockSnykCacheDirUtil) UserCacheDir() (string, error) {
	return m.cacheDir, m.cacheDirError
}

func (m *mockSnykCacheDirUtil) MkdirAll(path string, perm os.FileMode) error {
	m.dirPath = path
	m.dirPerm = perm
	return m.dirError
}

func NewMockSnykCacheDirUtil(cacheDir string, cacheDirError error, dirError error) SnykCacheDirUtil {
	return &mockSnykCacheDirUtil{cacheDir: cacheDir, cacheDirError: cacheDirError, dirError: dirError}
}

func Test_SnykCacheDir_returnsCacheDir(t *testing.T) {
	cacheDir := "path/to/cache/dir"
	expectedDirName := "snyk"
	expectedDir := path.Join(cacheDir, expectedDirName)

	osutil := NewMockSnykCacheDirUtil(cacheDir, nil, nil)

	cacheDir, err := SnykCacheDirImpl(osutil)
	assert.Nil(t, err)
	assert.Equal(t, expectedDir, cacheDir)
}

func Test_SnykCacheDir_handlesCacheDirErr(t *testing.T) {
	expectedDir := "snyk"
	expectedErr := errors.New("error getting cache dir")

	osutil := NewMockSnykCacheDirUtil("", expectedErr, nil)

	cacheDir, err := SnykCacheDirImpl(osutil)
	assert.Equal(t, "error getting cache dir", err.Error())
	assert.Equal(t, expectedDir, cacheDir)
}

func Test_FullPathInSnykCacheDir_returnsFullPath(t *testing.T) {
	expectedFullPath := "path/to/cache/dir/file"

	actualFullPath, err := FullPathInSnykCacheDir("path/to/cache/dir", "file")

	assert.Nil(t, err)
	assert.Equal(t, expectedFullPath, actualFullPath)
}
