package git

import (
	"os"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/stretchr/testify/assert"
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
