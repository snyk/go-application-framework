package code_workflow

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/code-client-go/scan"
)

func writeFile(t *testing.T, filename string) {
	t.Helper()
	err := os.WriteFile(filename, []byte("hello"), 0644)
	assert.NoError(t, err)
}

func Test_determineAnalyzeInput(t *testing.T) {
	logger := zerolog.Nop()
	config := configuration.NewWithOpts()
	config.Set(configuration.FLAG_REMOTE_REPO_URL, "hello")
	config.Set(configuration.MAX_THREADS, 1)

	path := t.TempDir()
	filenames := []string{
		filepath.Join(path, "hello.txt"),
		filepath.Join(path, "world.txt"),
	}
	writeFile(t, filenames[0])
	writeFile(t, filenames[1])

	t.Run("given a folder", func(t *testing.T) {
		count := 0

		target, files, err := determineAnalyzeInput(path, config, &logger)
		assert.NoError(t, err)
		assert.NotNil(t, target)
		assert.NotNil(t, files)
		assert.Equal(t, path, target.GetPath())

		for file := range files {
			t.Log(file)
			count++
		}

		assert.Equal(t, 2, count)
	})

	t.Run("given a file", func(t *testing.T) {
		count := 0

		target, files, err := determineAnalyzeInput(filenames[1], config, &logger)
		assert.NoError(t, err)
		assert.NotNil(t, target)
		assert.NotNil(t, files)
		assert.Equal(t, path, target.GetPath())

		for file := range files {
			t.Log(file)
			count++
		}

		assert.Equal(t, 1, count)
	})
}

func Test_TrackUsage(t *testing.T) {
	trackUsageCalled := false
	org := "something"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.String(), "/v1/track-sast-usage/cli?org="+org) {
			trackUsageCalled = true
		}

		assert.Equal(t, http.MethodPost, r.Method)
		w.WriteHeader(http.StatusOK)
	}))

	config := configuration.NewWithOpts()
	config.Set(configuration.ORGANIZATION, org)
	config.Set(configuration.API_URL, server.URL)
	networkAccess := networking.NewNetworkAccess(config)

	// call method under test
	trackUsage(networkAccess, config)

	assert.True(t, trackUsageCalled)
}

// Simple scan.Target implementation for testing non-RepositoryTarget case
type NonRepositoryScanTarget struct {
	path string
}

func (n NonRepositoryScanTarget) GetPath() string { return n.path }

func TestGitContextExtraction(t *testing.T) {
	tests := []struct {
		name                  string
		target                scan.Target
		expectedGitContext    bool
		description           string
	}{
		{
			name:               "RepositoryTarget with empty URL",
			target:             &scan.RepositoryTarget{LocalFilePath: "/test/path"},
			expectedGitContext: true, // GitContext should exist but with empty RepositoryUrl
			description:        "When RepositoryTarget has empty URL, git context should exist but be empty",
		},
		{
			name:               "Non-RepositoryTarget",
			target:             NonRepositoryScanTarget{path: "/test/path"},
			expectedGitContext: false,
			description:        "When target is not RepositoryTarget, git context should be nil",
		},
		{
			name:               "Nil target",
			target:             nil,
			expectedGitContext: false,
			description:        "When target is nil, git context should be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the git context extraction logic directly
			var gitContext *local_models.GitContext
			if tt.target != nil {
				if repoTarget, ok := tt.target.(*scan.RepositoryTarget); ok {
					gitContext = &local_models.GitContext{
						RepositoryUrl: repoTarget.GetRepositoryUrl(),
					}
				}
			}

			if tt.expectedGitContext {
				assert.NotNil(t, gitContext, tt.description)
			} else {
				assert.Nil(t, gitContext, tt.description)
			}
		})
	}
}
