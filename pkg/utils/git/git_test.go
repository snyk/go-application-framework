package git

import (
	"os"
	"os/exec"
	"path/filepath"
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

func TestStripGitCredentials(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string", "", ""},
		{"https with user and password", "https://user:password@github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"https with oauth2 token", "https://oauth2:ghp_abc123@github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"https with username only", "https://user@github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"http with credentials", "http://user:pass@gitlab.com/org/repo", "http://gitlab.com/org/repo"},
		{"malformed password with @ strips full userinfo", "https://user:p@ss@host:port8080/path", "https://host:port8080/path"},
		{"ssh with userinfo", "ssh://git@github.com/org/repo.git", "ssh://github.com/org/repo.git"},
		{"scp-style strips user", "git@github.com:org/repo.git", "github.com:org/repo.git"},
		{"scp-style with token user", "TOKEN@host:org/repo.git", "host:org/repo.git"},
		{"scp-style with deploy user", "deploy@gitlab.com:org/repo.git", "gitlab.com:org/repo.git"},
		{"scp-style with @ in path keeps path @", "git@github.com:org/repo@v2.git", "github.com:org/repo@v2.git"},
		{"scp-like without userinfo and @ in path unchanged", "github.com:org/repo@v2.git", "github.com:org/repo@v2.git"},
		{"clean https unchanged", "https://github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"git protocol no credentials", "git://github.com/org/repo.git", "git://github.com/org/repo.git"},
		{"malformed port with credentials", "https://user:pass@host:port8080/path", "https://host:port8080/path"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StripGitCredentials(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizeGitURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string", "", ""},
		{"scp-style", "git@github.com:org/repo.git", "https://github.com/org/repo.git"},
		{"scp-style without .git suffix", "git@github.com:org/repo", "https://github.com/org/repo.git"},
		{"ssh scheme", "ssh://git@github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"ssh scheme without .git suffix", "ssh://git@github.com/org/repo", "https://github.com/org/repo.git"},
		{"git protocol", "git://github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"http to https", "http://github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"https with .git suffix", "https://github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"https already clean", "https://github.com/org/repo", "https://github.com/org/repo.git"},
		{"https with credentials", "https://user:token@github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"http with credentials", "http://user:pass@gitlab.com/org/repo.git", "https://gitlab.com/org/repo.git"},
		{"https with port", "https://github.com:8443/org/repo.git", "https://github.com:8443/org/repo.git"},
		{"ssh with port", "ssh://git@github.com:22/org/repo.git", "https://github.com/org/repo.git"},
		{"ssh with non-standard port", "ssh://git@bitbucket.example.com:7999/project/repo.git", "https://bitbucket.example.com/project/repo.git"},
		{"git+ssh scheme", "git+ssh://git@github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"ssh+git scheme", "ssh+git://git@github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"git+http scheme", "git+http://github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"git+https scheme", "git+https://github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"gitlab subgroup scp-style", "git@gitlab.com:org/subgroup/repo.git", "https://gitlab.com/org/subgroup/repo.git"},
		{"scp-style with token user", "TOKEN@host:org/repo.git", "https://host/org/repo.git"},
		{"scp-style with deploy user", "deploy@gitlab.com:org/repo.git", "https://gitlab.com/org/repo.git"},
		{"malformed password with @ strips credentials", "https://user:p@ss@host:port8080/org/repo.git", "https://host:port8080/org/repo.git"},
		{"scp-like without userinfo and @ in path unchanged", "github.com:org/repo@v2.git", "github.com:org/repo@v2.git"},
		{"file protocol passthrough", "file:///home/user/repo.git", "file:///home/user/repo.git"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NormalizeGitURL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetRemoteUrl(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "git-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Initialize a git repository
	repo, err := git.PlainInit(tempDir, false)
	assert.NoError(t, err)

	// Add a remote
	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://github.com/test/repo.git"},
	})
	assert.NoError(t, err)

	// Test GetRemoteUrl
	remoteUrl, err := GetRemoteUrl(tempDir)
	assert.NoError(t, err)
	assert.Equal(t, "https://github.com/test/repo.git", remoteUrl)
}

func TestGetOriginRemote(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "git-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Initialize a git repository
	repo, err := git.PlainInit(tempDir, false)
	assert.NoError(t, err)

	// Add origin remote
	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://github.com/test/repo.git"},
	})
	assert.NoError(t, err)

	// Test GetOriginRemote
	remoteUrl, err := GetOriginRemote(tempDir)
	assert.NoError(t, err)
	assert.Equal(t, "https://github.com/test/repo.git", remoteUrl)
}

func TestGetFirstRemote(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "git-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Initialize a git repository
	repo, err := git.PlainInit(tempDir, false)
	assert.NoError(t, err)

	// Add a remote (not origin)
	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "upstream",
		URLs: []string{"https://github.com/upstream/repo.git"},
	})
	assert.NoError(t, err)

	// Test GetFirstRemote
	remoteUrl, err := GetFirstRemote(tempDir)
	assert.NoError(t, err)
	assert.Equal(t, "https://github.com/upstream/repo.git", remoteUrl)
}

func TestGetRemoteUrl_NoGitRepo(t *testing.T) {
	// Create a temporary directory that's not a git repo
	tempDir, err := os.MkdirTemp("", "not-git-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Test GetRemoteUrl should fail
	_, err = GetRemoteUrl(tempDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a git repository")
}

func TestGetRemoteUrl_NoRemotes(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "git-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Initialize a git repository without remotes
	_, err = git.PlainInit(tempDir, false)
	assert.NoError(t, err)

	// Test GetRemoteUrl should fail
	_, err = GetRemoteUrl(tempDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no remotes configured")
}

func TestTreeHashFromDir(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "git-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	repo, err := git.PlainInit(tempDir, false)
	require.NoError(t, err)

	worktree, err := repo.Worktree()
	require.NoError(t, err)

	// Write a known file so the resulting tree hash is deterministic. The tree
	// hash depends only on tracked content, not on commit metadata (author,
	// message, timestamp), so this value is stable across runs.
	err = os.WriteFile(filepath.Join(tempDir, "test.txt"), []byte("hello"), 0600)
	require.NoError(t, err)

	_, err = worktree.Add("test.txt")
	require.NoError(t, err)

	_, err = worktree.Commit("init", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "tester",
			Email: "tester@example.com",
			When:  time.Unix(0, 0),
		},
	})
	require.NoError(t, err)

	treeHash, err := TreeHashFromDir(tempDir)
	require.NoError(t, err)
	// Matches `git rev-parse HEAD^{tree}` for a single file "test.txt" == "hello".
	assert.Equal(t, "1f8f3dc0c09ab2e1e5c303031f4205c64eab8ef4", treeHash)
}

func TestTreeHashFromDir_NoGitRepo(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "not-git-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	_, err = TreeHashFromDir(tempDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a git repository")
}

func TestTreeHashFromDir_NoCommits(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "git-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	_, err = git.PlainInit(tempDir, false)
	require.NoError(t, err)

	// No commits yet, so HEAD cannot be resolved.
	_, err = TreeHashFromDir(tempDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to resolve HEAD")
}

func TestGetRemoteUrl_Priority(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "git-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Initialize a git repository
	repo, err := git.PlainInit(tempDir, false)
	assert.NoError(t, err)

	// Add multiple remotes
	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "upstream",
		URLs: []string{"https://github.com/upstream/repo.git"},
	})
	assert.NoError(t, err)

	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://github.com/origin/repo.git"},
	})
	assert.NoError(t, err)

	// Test GetRemoteUrl should prefer origin
	remoteUrl, err := GetRemoteUrl(tempDir)
	assert.NoError(t, err)
	assert.Equal(t, "https://github.com/origin/repo.git", remoteUrl)
}

func initRepoWithCommit(t *testing.T) (string, *git.Repository, string) {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)
	worktree, err := repo.Worktree()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello"), 0600))
	_, err = worktree.Add("test.txt")
	require.NoError(t, err)
	hash, err := worktree.Commit("init", &git.CommitOptions{
		Author: &object.Signature{Name: "tester", Email: "tester@example.com", When: time.Unix(0, 0)},
	})
	require.NoError(t, err)
	return dir, repo, hash.String()
}

func TestHeadCommitHashFromDir_RepoRoot(t *testing.T) {
	dir, _, expected := initRepoWithCommit(t)

	commitHash, err := HeadCommitHashFromDir(dir)

	require.NoError(t, err)
	assert.Equal(t, expected, commitHash)
}

func TestHeadCommitHashFromDir_Subdirectory(t *testing.T) {
	dir, _, expected := initRepoWithCommit(t)
	subDir := filepath.Join(dir, "services", "api")
	require.NoError(t, os.MkdirAll(subDir, 0700))

	commitHash, err := HeadCommitHashFromDir(subDir)

	require.NoError(t, err)
	assert.Equal(t, expected, commitHash)
}

func TestHeadCommitHashFromDir_DetachedHead(t *testing.T) {
	dir, repo, firstCommit := initRepoWithCommit(t)
	worktree, err := repo.Worktree()
	require.NoError(t, err)
	_, err = worktree.Commit("second", &git.CommitOptions{
		AllowEmptyCommits: true,
		Author:            &object.Signature{Name: "tester", Email: "tester@example.com", When: time.Unix(1, 0)},
	})
	require.NoError(t, err)
	require.NoError(t, worktree.Checkout(&git.CheckoutOptions{Hash: plumbing.NewHash(firstCommit)}))

	commitHash, err := HeadCommitHashFromDir(dir)

	require.NoError(t, err)
	assert.Equal(t, firstCommit, commitHash)
}

func TestHeadCommitHashFromDir_NoRemote(t *testing.T) {
	dir, repo, expected := initRepoWithCommit(t)
	remotes, err := repo.Remotes()
	require.NoError(t, err)
	require.Empty(t, remotes)

	commitHash, err := HeadCommitHashFromDir(dir)

	require.NoError(t, err)
	assert.Equal(t, expected, commitHash)
}

func TestHeadCommitHashFromDir_NotARepository(t *testing.T) {
	commitHash, err := HeadCommitHashFromDir(t.TempDir())

	require.NoError(t, err)
	assert.Empty(t, commitHash)
}

func TestHeadCommitHashFromDir_NoCommits(t *testing.T) {
	dir := t.TempDir()
	_, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	commitHash, err := HeadCommitHashFromDir(dir)

	require.NoError(t, err)
	assert.Empty(t, commitHash)
}

func TestResolveCommitId_ConfiguredCommitIdOverridesDetected(t *testing.T) {
	dir, _, _ := initRepoWithCommit(t)
	config := configuration.NewInMemory()
	config.Set(configuration.FLAG_COMMIT_ID, "0123456789abcdef0123456789abcdef01234567")

	commitId, err := ResolveCommitId(config, dir)

	require.NoError(t, err)
	assert.Equal(t, "0123456789abcdef0123456789abcdef01234567", commitId)
}

func TestResolveCommitId_FallsBackToDetectedCommit(t *testing.T) {
	dir, _, expected := initRepoWithCommit(t)

	commitId, err := ResolveCommitId(configuration.NewInMemory(), dir)

	require.NoError(t, err)
	assert.Equal(t, expected, commitId)
}

func TestHeadCommitHashFromDir_LinkedWorktree(t *testing.T) {
	dir, _, expected := initRepoWithCommit(t)
	worktreeDir := filepath.Join(t.TempDir(), "linked")
	cmd := exec.Command("git", "worktree", "add", "-b", "feat", worktreeDir)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "git worktree add: %s", out)
	subDir := filepath.Join(worktreeDir, "services")
	require.NoError(t, os.MkdirAll(subDir, 0700))

	for _, inputDir := range []string{worktreeDir, subDir} {
		commitHash, err := HeadCommitHashFromDir(inputDir)

		require.NoError(t, err)
		assert.Equal(t, expected, commitHash, inputDir)
	}
}
