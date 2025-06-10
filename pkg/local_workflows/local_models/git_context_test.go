package local_models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGitContextSerialization(t *testing.T) {
	// Test with git context
	gitContext := &GitContext{
		RepositoryUrl: "https://github.com/example/repo.git",
		Branch:        "main",
		CommitHash:    "abc123",
	}

	localFinding := LocalFinding{
		GitContext: gitContext,
		Links:      make(map[string]string),
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(localFinding)
	assert.NoError(t, err)

	// Deserialize from JSON
	var deserializedFinding LocalFinding
	err = json.Unmarshal(jsonData, &deserializedFinding)
	assert.NoError(t, err)

	// Verify git context is preserved
	assert.NotNil(t, deserializedFinding.GitContext)
	assert.Equal(t, "https://github.com/example/repo.git", deserializedFinding.GitContext.RepositoryUrl)
	assert.Equal(t, "main", deserializedFinding.GitContext.Branch)
	assert.Equal(t, "abc123", deserializedFinding.GitContext.CommitHash)
}

func TestGitContextCompleteSerialization(t *testing.T) {
	// Test with complete git context
	gitContext := &GitContext{
		RepositoryUrl: "https://github.com/example/repo.git",
		Branch:        "main",
		CommitHash:    "abc123def456",
	}

	localFinding := LocalFinding{
		GitContext: gitContext,
		Links:      make(map[string]string),
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(localFinding)
	assert.NoError(t, err)

	// Deserialize from JSON
	var deserializedFinding LocalFinding
	err = json.Unmarshal(jsonData, &deserializedFinding)
	assert.NoError(t, err)

	// Verify all git context fields are preserved
	assert.NotNil(t, deserializedFinding.GitContext)
	assert.Equal(t, "https://github.com/example/repo.git", deserializedFinding.GitContext.RepositoryUrl)
	assert.Equal(t, "main", deserializedFinding.GitContext.Branch)
	assert.Equal(t, "abc123def456", deserializedFinding.GitContext.CommitHash)
}

func TestGitContextNil(t *testing.T) {
	// Test without git context
	localFinding := LocalFinding{
		GitContext: nil,
		Links:      make(map[string]string),
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(localFinding)
	assert.NoError(t, err)

	// Deserialize from JSON
	var deserializedFinding LocalFinding
	err = json.Unmarshal(jsonData, &deserializedFinding)
	assert.NoError(t, err)

	// Verify git context is nil
	assert.Nil(t, deserializedFinding.GitContext)
}

func TestGitContextEmptyRepository(t *testing.T) {
	// Test with empty repository URL
	gitContext := &GitContext{
		RepositoryUrl: "",
		Branch:        "main",
		CommitHash:    "abc123",
	}

	localFinding := LocalFinding{
		GitContext: gitContext,
		Links:      make(map[string]string),
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(localFinding)
	assert.NoError(t, err)

	// Deserialize from JSON
	var deserializedFinding LocalFinding
	err = json.Unmarshal(jsonData, &deserializedFinding)
	assert.NoError(t, err)

	// Verify git context is preserved but repository URL is empty
	assert.NotNil(t, deserializedFinding.GitContext)
	assert.Equal(t, "", deserializedFinding.GitContext.RepositoryUrl)
	assert.Equal(t, "main", deserializedFinding.GitContext.Branch)
	assert.Equal(t, "abc123", deserializedFinding.GitContext.CommitHash)
}
