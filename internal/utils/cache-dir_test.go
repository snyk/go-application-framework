package utils

import (
	"errors"
	"fmt"
	"path"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/internal/mocks"
)

func Test_SnykCacheDir(t *testing.T) {
	t.Run("get default cache dir", func(t *testing.T) {
		dir := "path/to/cache/dir"
		expectedDirName := path.Join("snyk", "snyk-cli")
		expectedDir := path.Join(dir, expectedDirName)

		osutil := mocks.NewMockSnykOSUtil(gomock.NewController(t))
		osutil.EXPECT().UserCacheDir().Return(dir, nil)
		osutil.EXPECT().TempDir().Return(dir)
		osutil.EXPECT().MkdirAll(gomock.Any(), gomock.Any()).Return(nil)

		cacheDir, err := SnykCacheDirImpl(osutil)
		assert.NoError(t, err)
		assert.Equal(t, expectedDir, cacheDir)
	})

	t.Run("get default cache dir but keep error message", func(t *testing.T) {
		dir := "path/to/cache/dir"
		expectedDirName := path.Join("snyk", "snyk-cli")
		expectedDir := path.Join(dir, expectedDirName)

		osutil := mocks.NewMockSnykOSUtil(gomock.NewController(t))
		osutil.EXPECT().UserCacheDir().Return(dir, fmt.Errorf("user cache dir unknown"))
		osutil.EXPECT().TempDir().Return(dir)
		osutil.EXPECT().MkdirAll(gomock.Any(), gomock.Any()).Return(nil)

		cacheDir, err := SnykCacheDirImpl(osutil)
		assert.Error(t, err)
		assert.Equal(t, expectedDir, cacheDir)
	})

	t.Run("fall back to tmp dir based cache dir", func(t *testing.T) {
		dir := "/tmp"
		expectedDir := path.Join(dir, "snyk", "snyk-cli")

		osutil := mocks.NewMockSnykOSUtil(gomock.NewController(t))
		osutil.EXPECT().UserCacheDir().Return("/.cache", fmt.Errorf("something went wrong"))
		osutil.EXPECT().TempDir().Return(dir)
		osutil.EXPECT().MkdirAll(gomock.Any(), gomock.Any()).Return(errors.New("mkdir: failed to create dir"))
		osutil.EXPECT().MkdirAll(gomock.Any(), gomock.Any()).Return(nil)

		cacheDir, err := SnykCacheDirImpl(osutil)
		assert.Error(t, err)
		assert.Equal(t, expectedDir, cacheDir)
	})

	t.Run("fall back to sub dir based cache dir", func(t *testing.T) {
		expectedDir := path.Join("snyk", "snyk-cli")

		osutil := mocks.NewMockSnykOSUtil(gomock.NewController(t))
		osutil.EXPECT().UserCacheDir().Return("/.cache", fmt.Errorf("something went wrong"))
		osutil.EXPECT().TempDir().Return("/tmp")
		osutil.EXPECT().MkdirAll(gomock.Any(), gomock.Any()).Return(errors.New("mkdir: failed to create dir"))
		osutil.EXPECT().MkdirAll(gomock.Any(), gomock.Any()).Return(errors.New("mkdir: failed to create dir"))
		osutil.EXPECT().MkdirAll(gomock.Any(), gomock.Any()).Return(nil)

		cacheDir, err := SnykCacheDirImpl(osutil)
		assert.Error(t, err)
		assert.Equal(t, expectedDir, cacheDir)
	})

}

func Test_FullPathInSnykCacheDir_returnsFullPath(t *testing.T) {
	expectedFullPath := "path/to/cache/dir/file"

	actualFullPath, err := FullPathInSnykCacheDir("path/to/cache/dir", "file")

	assert.Nil(t, err)
	assert.Equal(t, expectedFullPath, actualFullPath)
}
