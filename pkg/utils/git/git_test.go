package git

import (
	"os"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/stretchr/testify/assert"
)

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

func TestGetSanitizedRemoteUrl(t *testing.T) {
	tests := []struct {
		name      string
		remoteUrl string
		expected  string
	}{
		{
			name:      "https url",
			remoteUrl: "https://github.com/snyk/go-application-framework.git",
			expected:  "http://github.com/snyk/go-application-framework.git",
		},
		{
			name:      "http url",
			remoteUrl: "http://github.com/snyk/go-application-framework.git",
			expected:  "http://github.com/snyk/go-application-framework.git",
		},
		{
			name:      "ssh url with protocol",
			remoteUrl: "ssh://git@github.com/snyk/go-application-framework.git",
			expected:  "http://github.com/snyk/go-application-framework.git",
		},
		{
			name:      "scp-like syntax",
			remoteUrl: "git@github.com:snyk/go-application-framework.git",
			expected:  "http://github.com/snyk/go-application-framework.git",
		},
		{
			name:      "scp-like syntax no user",
			remoteUrl: "github.com:snyk/go-application-framework.git",
			expected:  "http://github.com/snyk/go-application-framework.git",
		},
		{
			name:      "empty url",
			remoteUrl: "",
			expected:  "",
		},
		{
			name:      "invalid url no change",
			remoteUrl: "not-a-valid-url",
			expected:  "not-a-valid-url",
		},
		{
			name:      "ftp url fallback to regex (weird behavior matching nodejs)",
			remoteUrl: "ftp://github.com/snyk/go.git",
			expected:  "http://ftp///github.com/snyk/go.git",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := NormalizeRemoteURL(tt.remoteUrl)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
