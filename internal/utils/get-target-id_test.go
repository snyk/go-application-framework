package utils

import (
	"fmt"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/assert"
)

func Test_GetTargetId(t *testing.T) {
	t.Run("handles a filesystem directory path", func(t *testing.T) {
		tempDir := t.TempDir()
		targetId, err := GetTargetId(tempDir)
		assert.NoError(t, err)

		pattern := `^pkg:filesystem/[a-fA-F0-9]{64}/001$`

		matched, err := regexp.MatchString(pattern, targetId)
		assert.NoError(t, err)
		assert.True(t, matched)
	})

	t.Run("handles a file directory path", func(t *testing.T) {
		tempDir := t.TempDir()
		tempFile1 := filepath.Join(tempDir, "test1.ts")
		targetId, err := GetTargetId(tempFile1)
		assert.NoError(t, err)

		pattern := `^pkg:filesystem/[a-fA-F0-9]{64}/001#test1.ts$`

		matched, err := regexp.MatchString(pattern, targetId)
		assert.NoError(t, err)
		assert.True(t, matched)
	})

	t.Run("handles a directory which has a .git file at the root", func(t *testing.T) {

		expectedRepoUrl := "https://github.com/snyk-fixtures/shallow-goof-locked.git"
		tempDir, _ := clone(t, expectedRepoUrl, "")

		targetId, err := GetTargetId(tempDir)
		assert.NoError(t, err)

		pattern := `^pkg:git/github\.com/snyk-fixtures/shallow-goof-locked@[a-fA-F0-9]{40}\?branch=master$`
		fmt.Println(targetId)
		matched, err := regexp.MatchString(pattern, targetId)
		assert.NoError(t, err)
		assert.True(t, matched)
	})
}

func clone(t *testing.T, repoUrl string, repoDir string) (string, *git.Repository) {
	t.Helper()

	if repoDir == "" {
		repoDir = t.TempDir()
	}
	repo, err := git.PlainClone(repoDir, false, &git.CloneOptions{URL: repoUrl})
	assert.NoError(t, err)
	assert.NotNil(t, repo)

	return repoDir, repo
}
