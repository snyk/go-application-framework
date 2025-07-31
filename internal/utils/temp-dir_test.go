package utils

import (
	"errors"
	"log"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockTempDirOSUtil struct {
	tempDir    string
	dirPath    string
	dirPerm    os.FileMode
	mkDirError error
	statError  error
}

func (m *mockTempDirOSUtil) UserCacheDir() (string, error) {
	return "", nil
}

func (m *mockTempDirOSUtil) MkdirAll(path string, perm os.FileMode) error {
	m.dirPath = path
	m.dirPerm = perm
	return m.mkDirError
}

func (m *mockTempDirOSUtil) Stat(name string) (os.FileInfo, error) {
	return nil, m.statError
}

func (m *mockTempDirOSUtil) TempDir() string {
	return m.tempDir
}

func newmockSnykOSUtil(tempDir string, mkDirError error, statError error) SnykOSUtil {
	return &mockTempDirOSUtil{
		tempDir:    tempDir,
		mkDirError: mkDirError,
		statError:  statError,
	}
}

func Test_systemTempDirectory_getsSysTempDir(t *testing.T) {
	expectedDir := "path/to/temp/dir"
	logger := log.New(os.Stderr, "test", 0)

	osutil := newmockSnykOSUtil(expectedDir, nil, nil)

	tempDir, err := systemTempDirectory(logger, osutil)
	assert.Nil(t, err)
	assert.Equal(t, expectedDir, tempDir)
}

func Test_systemTempDirectory_handlesWhenTempDirNotExists(t *testing.T) {
	expectedDir := "path/to/temp/dir"
	logger := log.New(os.Stderr, "test", 0)
	statError := errors.New("os.Stat error")

	osutil := newmockSnykOSUtil(expectedDir, nil, statError)

	tempDir, err := systemTempDirectory(logger, osutil)
	assert.Nil(t, err)
	assert.Equal(t, expectedDir, tempDir)
	assert.Equal(t, expectedDir, osutil.(*mockTempDirOSUtil).dirPath)  //nolint:errcheck //in this test, the type is fix
	assert.Equal(t, FILEPERM_755, osutil.(*mockTempDirOSUtil).dirPerm) //nolint:errcheck //in this test, the type is fix
}

func Test_systemTempDirectory_handlesTempDirFailure(t *testing.T) {
	logger := log.New(os.Stderr, "test", 0)
	mkDirError := errors.New("os.MkdirAll error")
	statError := errors.New("os.Stat error")

	osutil := newmockSnykOSUtil("someDir", mkDirError, statError)

	tempDir, err := systemTempDirectory(logger, osutil)
	assert.Equal(t, "", tempDir)
	assert.Equal(t, mkDirError.Error(), err.Error())
}

func Test_snykTempDirectoryImpl_returnsTempDir(t *testing.T) {
	expectedFile := "snyk"
	expectedDir := "path/to/temp/dir"
	expectedResult := path.Join(expectedDir, expectedFile)
	logger := log.New(os.Stderr, "test", 0)

	osutil := newmockSnykOSUtil(expectedDir, nil, nil)

	tempDir, err := snykTempDirectoryImpl(logger, osutil)
	assert.Nil(t, err)
	assert.Equal(t, expectedResult, tempDir)
}

func Test_snykTempDirectoryImpl_handlesWhenSnykTempDirNotExists(t *testing.T) {
	expectedFile := "snyk"
	expectedDir := "path/to/temp/dir"
	expectedResult := path.Join(expectedDir, expectedFile)
	logger := log.New(os.Stderr, "test", 0)
	statError := errors.New("os.Stat error")

	osutil := newmockSnykOSUtil(expectedDir, nil, statError)

	tempDir, err := snykTempDirectoryImpl(logger, osutil)
	assert.Nil(t, err)
	assert.Equal(t, expectedResult, tempDir)
	assert.Equal(t, expectedResult, osutil.(*mockTempDirOSUtil).dirPath) //nolint:errcheck //in this test, the type is fix
	assert.Equal(t, FILEPERM_755, osutil.(*mockTempDirOSUtil).dirPerm)   //nolint:errcheck //in this test, the type is fix
}

func Test_snykTempDirectoryImpl_handlesSnykTempDirFailure(t *testing.T) {
	logger := log.New(os.Stderr, "test", 0)
	mkDirError := errors.New("os.MkdirAll error")
	statError := errors.New("os.Stat error")

	osutil := newmockSnykOSUtil("someDir", mkDirError, statError)

	tempDir, err := snykTempDirectoryImpl(logger, osutil)
	assert.Equal(t, "", tempDir)
	assert.Equal(t, mkDirError.Error(), err.Error())
}
