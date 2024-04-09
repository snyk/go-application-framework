package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileWalker_GetAllFiles(t *testing.T) {
	//ignoreFiles := []string{".gitignore"}
	tempDir := t.TempDir()
	tempFile1 := filepath.Join(tempDir, "test1.ts")
	createFileInPath(tempFile1, []byte{}, t)
	tempFile2 := filepath.Join(tempDir, "test2.ts")
	createFileInPath(tempFile2, []byte{}, t)

	fileWalker := NewFileWalker(tempDir)
	actualFiles := fileWalker.GetAllFiles()
	expectedFiles := []string{tempFile1, tempFile2}

	var actualFilesChanLen int
	for actualFile := range actualFiles {
		actualFilesChanLen++
		assert.Contains(t, expectedFiles, actualFile)
	}
	assert.Equal(t, len(expectedFiles), actualFilesChanLen)
}

func TestFileWalker_GetRules(t *testing.T) {
	// create temp filesystem
	tempDir := t.TempDir()
	tempFile1 := filepath.Join(tempDir, "test1.ts")
	createFileInPath(tempFile1, []byte{}, t)
	tempFile2 := filepath.Join(tempDir, "test2.ts")
	createFileInPath(tempFile2, []byte{}, t)
	ignoreFile := filepath.Join(tempDir, ".gitignore")
	createFileInPath(ignoreFile, []byte(".git\ntest1.ts\n"), t)

	// create expected rules
	expectedRules := []string{
		fmt.Sprintf("%s/**/.git/**", tempDir), // apply ignore in all subDirs
		fmt.Sprintf("%s/**/.git", tempDir),    // apply ignore in curDir
		fmt.Sprintf("%s/**/test1.ts/**", tempDir),
		fmt.Sprintf("%s/**/test1.ts", tempDir),
	}

	// create fileWalker
	fileWalker := NewFileWalker(tempDir)
	actualRules, err := fileWalker.GetRules()
	assert.NoError(t, err)

	assert.Equal(t, expectedRules, actualRules)
}

//func TestFileWalker_GetIgnoreFiles(t *testing.T) {
//	ignoreFiles := []string{".gitignore"}
//	tempDir := t.TempDir()
//	tempSubDir := filepath.Join(tempDir, "tempSubDir")
//	err := os.Mkdir(tempSubDir, os.ModePerm)
//	assert.NoError(t, err)
//
//	createFileInPath(filepath.Join(tempDir, "test1.ts"), []byte{}, t)
//	createFileInPath(filepath.Join(tempDir, "test2.ts"), []byte{}, t)
//	createFileInPath(filepath.Join(tempSubDir, "test3.ts"), []byte{}, t)
//
//	expectedFile := filepath.Join(tempSubDir, ".gitignore")
//	createFileInPath(expectedFile, []byte{}, t)
//	expectedIgnoreFileCount := 1
//
//	// GetFile() asynchronously returns all files in the filesystem
//	// Filter() listens to the result of GetAllFiles() and applies filter rules.
//	// GetRules() retuns an array of all gitignor ... files in the specified path
//	// how to load the filter rules, so that they are available for the first file in each directory
//	fileWalker := NewFileWalker(path)
//	channel := fileWarker.Filter(fileWarker.GetFile(), fileWalker.GetRules())
//
//	fileWalker := NewFileWalker(ignoreFiles)
//	files, err := fileWalker.GetAllFiles(tempDir)
//	assert.NoError(t, err)
//
//	actualFiles, err := fileWalker.GetIgnoreFiles(files)
//	assert.NoError(t, err)
//
//	var actualFilesChanLen int
//	for _, actualFile := range actualFiles {
//		actualFilesChanLen++
//		assert.Contains(t, expectedFile, actualFile)
//	}
//	assert.Equal(t, expectedIgnoreFileCount, actualFilesChanLen)
//}

//func TestFileWalker_GetFilesFilterIgnored(t *testing.T) {
//	ignoreFiles := []string{".gitignore"}
//	tempDir := t.TempDir()
//	tempSubDir := t.TempDir()
//	filepath.Join(tempDir, "test1.ts")
//	filepath.Join(tempDir, "test2.ts")
//	filepath.Join(tempDir, tempSubDir, "test3.ts")
//
//	createGitIgnoreFile(tempDir, []string{"test1.ts", filepath.Join(tempDir, tempSubDir)})
//
//	fileWalker := NewFileWalker(ignoreFiles)
//
//	actualFilesFiltered, err := fileWalker.GetFilesFilterIgnored(tempDir)
//	assert.NoError(t, err)
//
//	expectedFile := "test2.ts"
//
//	for actualFileFiltered := range actualFilesFiltered {
//		assert.Contains(t, expectedFile, actualFileFiltered)
//	}
//}

func createGitIgnoreFile(path string, ignoredFiles []string, t *testing.T) {
	t.Helper()
	var data []byte
	for _, ignoredFile := range ignoredFiles {
		data = append(data, []byte(ignoredFile+"\n")...)
	}

	gitIgnorePath := filepath.Join(path, ".gitignore")
	createFileInPath(gitIgnorePath, data, t)
}

func createFileInPath(filePath string, content []byte, t *testing.T) {
	t.Helper()
	err := os.WriteFile(filePath, content, 0777)
	assert.NoError(t, err)
}
