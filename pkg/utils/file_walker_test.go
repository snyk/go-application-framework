package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFileWalker_GetAllFiles_getsAllFilesForPath(t *testing.T) {
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

func TestFileWalker_GetRules_includesDotGitRuleByDefault(t *testing.T) {
	// create temp filesystem
	tempDir := t.TempDir()
	tempFile1 := filepath.Join(tempDir, "test1.ts")
	createFileInPath(tempFile1, []byte{}, t)
	tempFile2 := filepath.Join(tempDir, "test2.ts")
	createFileInPath(tempFile2, []byte{}, t)

	// expected rules should include .git rule by default
	expectedRules := []string{"**/.git/**", "**/.gitignore/**"}

	// create fileWalker
	fileWalker := NewFileWalker(tempDir)
	actualRules, err := fileWalker.GetRules([]string{})
	assert.NoError(t, err)

	assert.Equal(t, expectedRules, actualRules)
}

func TestFileWalker_GetRules_getsIgnoreRulesForPath(t *testing.T) {
	// create temp filesystem
	tempDir := t.TempDir()
	tempFile1 := filepath.Join(tempDir, "test1.ts")
	createFileInPath(tempFile1, []byte{}, t)
	tempFile2 := filepath.Join(tempDir, "test2.ts")
	createFileInPath(tempFile2, []byte{}, t)
	ignoreFile := filepath.Join(tempDir, ".gitignore")
	createFileInPath(ignoreFile, []byte("test1.ts\n"), t)

	// create expected rules
	expectedRules := []string{
		"**/.git/**",
		"**/.gitignore/**",
		fmt.Sprintf("%s/**/test1.ts/**", tempDir), // apply ignore in subDirs
		fmt.Sprintf("%s/**/test1.ts", tempDir),    // apply ignore in curDir
	}

	// create fileWalker
	ruleFiles := []string{".gitignore"}
	fileWalker := NewFileWalker(tempDir)
	actualRules, err := fileWalker.GetRules(ruleFiles)
	assert.NoError(t, err)

	assert.Equal(t, expectedRules, actualRules)
}

func TestFileWalker_GetFilteredFiles_filtersFiles(t *testing.T) {
	// create temp filesystem
	tempDir := t.TempDir()
	tempSubDir := filepath.Join(tempDir, "tempSubDir")
	err := os.Mkdir(tempSubDir, os.ModePerm)
	assert.NoError(t, err)

	// create ignore file in root dir ignoring any file with name 'test1.ts'
	ignoreFile := filepath.Join(tempDir, ".gitignore")
	createFileInPath(ignoreFile, []byte("test1.ts\n"), t)

	// create files in root dir
	tempFile1 := filepath.Join(tempDir, "test1.ts")
	createFileInPath(tempFile1, []byte{}, t)
	tempFile2 := filepath.Join(tempDir, "test2.ts")
	createFileInPath(tempFile2, []byte{}, t)

	// create files in sub dir
	tempSubFile1 := filepath.Join(tempSubDir, "test1.ts")
	createFileInPath(tempSubFile1, []byte{}, t)
	tempSubFile2 := filepath.Join(tempSubDir, "test2.ts")
	createFileInPath(tempSubFile2, []byte{}, t)

	// create fileWalker
	ruleFiles := []string{".gitignore"}
	fileWalker := NewFileWalker(tempDir)

	// get and filter files
	files := fileWalker.GetAllFiles()
	globs, err := fileWalker.GetRules(ruleFiles)
	assert.NoError(t, err)
	filteredFiles := fileWalker.GetFilteredFiles(files, globs)

	// set expected files
	expectedFiles := []string{
		fmt.Sprintf("%s/test2.ts", tempDir),
		fmt.Sprintf("%s/test2.ts", tempSubDir),
	}

	// assert files are filtered correctly
	var actualFilteredFilesLen int
	for file := range filteredFiles {
		actualFilteredFilesLen++
		assert.Contains(t, expectedFiles, file)
	}

	assert.Equal(t, len(expectedFiles), actualFilteredFilesLen)
}

func createFileInPath(filePath string, content []byte, t *testing.T) {
	t.Helper()
	err := os.WriteFile(filePath, content, 0777)
	assert.NoError(t, err)
}
