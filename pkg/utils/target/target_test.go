package target

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_GetTargetId(t *testing.T) {
	t.Run("handles a filesystem directory path", func(t *testing.T) {
		tempDir := t.TempDir()
		targetId, err := GetTargetId(tempDir, AutoDetectedTargetId, WithSubPath("myfile.go"))
		assert.NoError(t, err)

		pattern := `^pkg:filesystem/[a-fA-F0-9]{64}/001#myfile.go$`
		assert.Regexp(t, pattern, targetId)
	})

	t.Run("handles a file directory path", func(t *testing.T) {
		tempDir := t.TempDir()
		tempFile1 := filepath.Join(tempDir, "test1.ts")
		targetId, err := GetTargetId(tempFile1, AutoDetectedTargetId, WithSubPath("test1.ts"))
		assert.NoError(t, err)

		pattern := `^pkg:filesystem/[a-fA-F0-9]{64}/001#test1.ts$`
		assert.Regexp(t, pattern, targetId)
	})

	t.Run("handles paths with special characters", func(t *testing.T) {
		tempDir := t.TempDir()
		targetId, err := GetTargetId(tempDir, AutoDetectedTargetId, WithSubPath("filecontaining>specialcharacters123<.ts"))
		assert.NoError(t, err)

		pattern := `^pkg:filesystem/[a-fA-F0-9]{64}/001#filecontaining\%3Especialcharacters123\%3C.ts$`
		assert.Regexp(t, pattern, targetId)
	})

	t.Run("handles a directory which has a .git file at the root", func(t *testing.T) {
		tempDir := clone(t)

		targetId, err := GetTargetId(tempDir, AutoDetectedTargetId)
		assert.NoError(t, err)

		pattern := `^pkg:git/github\.com/snyk-fixtures/shallow-goof-locked@[a-fA-F0-9]{40}\?branch=master$`
		assert.Regexp(t, pattern, targetId)

		targetId, err = GetTargetId(tempDir, FilesystemTargetId, WithConfiguredRepository(configuration.NewInMemory()))
		assert.NoError(t, err)

		pattern = `^pkg:filesystem/[a-fA-F0-9]{64}/001$`
		assert.Regexp(t, pattern, targetId)
	})

	t.Run("falls back to filesystem due to invalid repo", func(t *testing.T) {
		tempDir := clone(t)

		// Remove HEAD ref to break git
		headFile := filepath.Join(tempDir, ".git", "HEAD")
		err := os.Remove(headFile)
		assert.NoError(t, err)

		targetId, err := GetTargetId(tempDir, AutoDetectedTargetId)
		assert.NoError(t, err)

		pattern := `^pkg:filesystem/[a-fA-F0-9]{64}/001$`
		assert.Regexp(t, pattern, targetId)

		// try to force a Git Target ID
		targetId, err = GetTargetId(tempDir, GitTargetId)
		assert.Error(t, err)
		assert.Empty(t, targetId)
	})

	t.Run("fails back to filesystem if invalid git url configured", func(t *testing.T) {
		tempDir := clone(t)

		// Update .git/config file to include empty url
		err := updateFile(t, tempDir+"/.git/config", "https://github.com/snyk-fixtures/shallow-goof-locked.git", "")
		assert.NoError(t, err)

		targetId, err := GetTargetId(tempDir, AutoDetectedTargetId, WithSubPath("package.json"))
		assert.NoError(t, err)

		pattern := `^pkg:filesystem/[a-fA-F0-9]{64}/001#package.json$`
		assert.Regexp(t, pattern, targetId)
	})

	t.Run("handles a git directory with a file location", func(t *testing.T) {
		tempDir := clone(t)

		targetId, err := GetTargetId(tempDir, AutoDetectedTargetId, WithSubPath("package.json"))
		assert.NoError(t, err)

		pattern := `^pkg:git/github\.com/snyk-fixtures/shallow-goof-locked@[a-fA-F0-9]{40}\?branch=master#package.json$`
		assert.Regexp(t, pattern, targetId)
	})

	t.Run("sanitize git url if it contains credentials", func(t *testing.T) {
		tempDir := clone(t)

		// Edit .git/config file to adjust remote url
		err := updateFile(t, tempDir+"/.git/config", "https://github.com/snyk-fixtures/shallow-goof-locked.git", "https://username:password@github.com/snyk-fixtures/shallow-goof-locked.git")
		assert.NoError(t, err)

		targetId, err := GetTargetId(tempDir, AutoDetectedTargetId, WithSubPath("package.json"))
		assert.NoError(t, err)

		pattern := `^pkg:git/github\.com/snyk-fixtures/shallow-goof-locked@[a-fA-F0-9]{40}\?branch=master#package.json$`
		assert.Regexp(t, pattern, targetId)
	})

	t.Run("Failed Options test", func(t *testing.T) {
		failingOption := func(id *url.URL) (*url.URL, error) {
			return nil, fmt.Errorf("failed to apply option")
		}

		tempDir := clone(t)
		targetId, err := GetTargetId(tempDir, AutoDetectedTargetId, WithSubPath("package.json"), failingOption)
		assert.Error(t, err)
		assert.Empty(t, targetId)
	})

	t.Run("different git repo urls, same output", func(t *testing.T) {
		expected := "git/github.com/snyk/cli"
		actual, err := gitBaseIdFromRemote("git@github.com:snyk/cli.git")
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)

		actual, err = gitBaseIdFromRemote("https://github.com/snyk/cli.git")
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)

		actual, err = gitBaseIdFromRemote("something@wrong:snyk/cli.git")
		assert.Error(t, err)
		assert.Empty(t, actual)
	})

	t.Run("Use absolute and relative directories", func(t *testing.T) {
		relativeDir := "./"
		absoluteDir, err := os.Getwd()
		assert.NoError(t, err)

		actualRelative, err := filesystemBaseId(relativeDir)
		assert.NoError(t, err)

		actualAbsolute, err := filesystemBaseId(absoluteDir)
		assert.NoError(t, err)

		assert.Equal(t, actualAbsolute, actualRelative)
	})

	t.Run("configured valid repo url", func(t *testing.T) {
		config := configuration.NewInMemory()
		config.Set(RemoteRepoUrlFlagname, "https://github.com/snyk/cli.git")

		tempDir := clone(t)
		targetId, err := GetTargetId(tempDir, AutoDetectedTargetId, WithLineNumber(23), WithSubPath("package.json"), WithConfiguredRepository(config))
		assert.NoError(t, err)

		pattern := `^pkg:git/github\.com/snyk/cli@unknown\?branch=unknown&line=23#package.json$`
		assert.Regexp(t, pattern, targetId)
	})

	t.Run("configured broken repo url", func(t *testing.T) {
		config := configuration.NewInMemory()
		config.Set(RemoteRepoUrlFlagname, "broken :23")

		tempDir := clone(t)
		targetId, err := GetTargetId(tempDir, AutoDetectedTargetId, WithLineNumber(23), WithSubPath("package.json"), WithConfiguredRepository(config))
		assert.Error(t, err)
		assert.Empty(t, targetId)
	})
}

func Test_GetTargetId_linkedWorktree(t *testing.T) {
	worktreeDir := linkedWorktreeFixture(t, "https://github.com/example/repo.git", "feature")

	targetId, err := GetTargetId(worktreeDir, AutoDetectedTargetId)
	assert.NoError(t, err)

	pattern := `^pkg:git/github\.com/example/repo@[a-fA-F0-9]{40}\?branch=feature$`
	assert.Regexp(t, pattern, targetId)
}

// linkedWorktreeFixture builds a main repository with one commit, a branch and an origin remote,
// then lays out a linked worktree at the returned path the way `git worktree add` does.
func linkedWorktreeFixture(t *testing.T, originUrl string, branch string) string {
	t.Helper()
	mainDir := t.TempDir()
	repo, err := git.PlainInit(mainDir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(mainDir, "README.md"), []byte("readme"), 0o600))
	_, err = wt.Add("README.md")
	require.NoError(t, err)
	hash, err := wt.Commit("initial commit", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	})
	require.NoError(t, err)
	require.NoError(t, repo.Storer.SetReference(plumbing.NewHashReference(plumbing.NewBranchReferenceName(branch), hash)))
	_, err = repo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{originUrl}})
	require.NoError(t, err)

	privateDir := filepath.Join(mainDir, ".git", "worktrees", "wt")
	require.NoError(t, os.MkdirAll(privateDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(privateDir, "HEAD"), []byte("ref: refs/heads/"+branch+"\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(privateDir, "commondir"), []byte("../..\n"), 0o600))

	worktreeDir := filepath.Join(t.TempDir(), "wt")
	require.NoError(t, os.MkdirAll(worktreeDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(worktreeDir, ".git"), []byte("gitdir: "+privateDir+"\n"), 0o600))

	return worktreeDir
}

func clone(t *testing.T) string {
	t.Helper()
	repoUrl := "https://github.com/snyk-fixtures/shallow-goof-locked.git"
	repoDir := t.TempDir()
	repo, err := git.PlainClone(repoDir, false, &git.CloneOptions{URL: repoUrl})
	assert.NoError(t, err)
	assert.NotNil(t, repo)

	return repoDir
}

func updateFile(t *testing.T, filePath, target, replacement string) error {
	t.Helper()
	file, err := os.Open(filePath)
	assert.NoError(t, err)
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	var updatedLines []string

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, target) {
			newLine := strings.Replace(line, target, replacement, -1)
			updatedLines = append(updatedLines, newLine)
		} else {
			updatedLines = append(updatedLines, line)
		}
	}

	err = scanner.Err()
	if err != nil {
		return err
	}

	// Write updated content back to the file
	newFile, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer newFile.Close()

	writer := bufio.NewWriter(newFile)
	for _, line := range updatedLines {
		_, err = writer.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}

	return writer.Flush()
}
