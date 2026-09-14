package target

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_ParseGitTargetId(t *testing.T) {
	t.Run("parses a git target id", func(t *testing.T) {
		gitTarget, ok := ParseGitTargetId("pkg:git/github.com/snyk/go-application-framework@c9cc908c69bc6d8cc4715275f9c19fa3be69aebc?branch=main")
		assert.True(t, ok)
		assert.Equal(t, "github.com/snyk/go-application-framework", gitTarget.Namespace)
		assert.Equal(t, "go-application-framework", gitTarget.Repository)
		assert.Equal(t, "c9cc908c69bc6d8cc4715275f9c19fa3be69aebc", gitTarget.Commit)
		assert.Equal(t, "main", gitTarget.Branch)
	})

	t.Run("ignores an optional subpath", func(t *testing.T) {
		gitTarget, ok := ParseGitTargetId("pkg:git/github.com/snyk/go-application-framework@c9cc908c?branch=main#cliv2/go.mod")
		assert.True(t, ok)
		assert.Equal(t, "go-application-framework", gitTarget.Repository)
		assert.Equal(t, "c9cc908c", gitTarget.Commit)
		assert.Equal(t, "main", gitTarget.Branch)
	})

	t.Run("handles a namespace with subgroups and a branch containing a slash", func(t *testing.T) {
		gitTarget, ok := ParseGitTargetId("pkg:git/gitlab.com/group/subgroup/repo@abc123?branch=feature/foo")
		assert.True(t, ok)
		assert.Equal(t, "gitlab.com/group/subgroup/repo", gitTarget.Namespace)
		assert.Equal(t, "repo", gitTarget.Repository)
		assert.Equal(t, "abc123", gitTarget.Commit)
		assert.Equal(t, "feature/foo", gitTarget.Branch)
	})

	t.Run("handles a missing branch qualifier", func(t *testing.T) {
		gitTarget, ok := ParseGitTargetId("pkg:git/github.com/snyk/repo@deadbeef")
		assert.True(t, ok)
		assert.Equal(t, "repo", gitTarget.Repository)
		assert.Equal(t, "deadbeef", gitTarget.Commit)
		assert.Empty(t, gitTarget.Branch)
	})

	t.Run("rejects a filesystem target id", func(t *testing.T) {
		_, ok := ParseGitTargetId("pkg:filesystem/aafc908c69bc6d8cc4715275f9c19fa3be69aebc/name#cliv2/go.mod")
		assert.False(t, ok)
	})

	t.Run("rejects a non-target string", func(t *testing.T) {
		_, ok := ParseGitTargetId("not-a-target-id")
		assert.False(t, ok)
	})

	t.Run("round-trips an id built by this package's encoder", func(t *testing.T) {
		id := emptyTargetId()
		err := gitUpdateId("https://github.com/snyk/myrepo.git", "abcdef123456", "main", id)
		assert.NoError(t, err)

		gitTarget, ok := ParseGitTargetId(id.String())
		assert.True(t, ok)
		assert.Equal(t, "github.com/snyk/myrepo", gitTarget.Namespace)
		assert.Equal(t, "myrepo", gitTarget.Repository)
		assert.Equal(t, "abcdef123456", gitTarget.Commit)
		assert.Equal(t, "main", gitTarget.Branch)
	})
}

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
