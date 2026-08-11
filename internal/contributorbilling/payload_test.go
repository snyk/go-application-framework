package contributorbilling

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarshalIngestPayload_MatchesGoldenFixture(t *testing.T) {
	t.Parallel()

	contributors := []Contributor{
		{
			Email:            "alice@example.com",
			LatestCommitDate: time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
		},
		{
			Email:            "bob@example.com",
			LatestCommitDate: time.Date(2026, 1, 10, 8, 30, 0, 0, time.UTC),
		},
	}

	item := BillingItem{
		EntityID:     "22222222-2222-2222-2222-222222222222",
		Contributors: contributors,
	}

	body, err := json.Marshal(buildIngestRequest(item, nil))
	require.NoError(t, err)

	goldenPath := filepath.Join("testdata", "golden_ingest_payload.json")
	golden, err := os.ReadFile(goldenPath)
	require.NoError(t, err)

	var got map[string]interface{}
	var want map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &got))
	require.NoError(t, json.Unmarshal(golden, &want))
	assert.Equal(t, want, got)
}

func TestMarshalIngestPayload_SkipsZeroLatestCommitDate(t *testing.T) {
	t.Parallel()

	item := BillingItem{
		EntityID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Contributors: []Contributor{
			{Email: "valid@example.com", LatestCommitDate: time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)},
			{Email: "invalid@example.com"},
		},
	}

	body, err := json.Marshal(buildIngestRequest(item, nil))
	require.NoError(t, err)

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &got))

	data, ok := got["data"].(map[string]interface{})
	require.True(t, ok)
	attributes, ok := data["attributes"].(map[string]interface{})
	require.True(t, ok)
	contributors, ok := attributes["contributors"].([]interface{})
	require.True(t, ok)
	require.Len(t, contributors, 1)

	contributor, ok := contributors[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "valid@example.com", contributor["email"])
	assert.Equal(t, "2026-01-15T12:00:00Z", contributor["commit_date"])
}

func TestContributorsEntityType_DefaultsToProject(t *testing.T) {
	t.Parallel()

	assert.Equal(t, EntityTypeProject, contributorsEntityType(BillingItem{
		EntityID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	}))
}

func TestContributorsEntityType_UsesExplicitEntityType(t *testing.T) {
	t.Parallel()

	assert.Equal(t, EntityTypeTarget, contributorsEntityType(BillingItem{
		EntityID:   "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		EntityType: EntityTypeTarget,
	}))
}

func TestContributorsEntityID_ReturnsBareUUID(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "dddddddd-dddd-4ddd-8ddd-dddddddddddd", contributorsEntityID(BillingItem{
		EntityID:   "  dddddddd-dddd-4ddd-8ddd-dddddddddddd  ",
		EntityType: EntityTypeTarget,
	}))
}

func TestCloneItem(t *testing.T) {
	t.Parallel()

	original := BillingItem{
		EntityID:   "project-a",
		EntityType: EntityTypeTarget,
		RepoPath:   "repo-a",
		Contributors: []Contributor{
			{Email: "dev@example.com", LatestCommitDate: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		},
	}

	cloned := cloneItem(original)

	original.EntityID = "mutated"
	original.EntityType = EntityTypeProject
	original.RepoPath = "mutated-repo"
	original.Contributors[0].Email = "mutated@example.com"

	assert.Equal(t, "project-a", cloned.EntityID)
	assert.Equal(t, EntityTypeTarget, cloned.EntityType)
	assert.True(t, filepath.IsAbs(cloned.RepoPath))
	assert.Contains(t, cloned.RepoPath, "repo-a")
	assert.Equal(t, "dev@example.com", cloned.Contributors[0].Email)
}

func TestValidateRequiredFields(t *testing.T) {
	t.Parallel()

	t.Run("empty capability is allowed", func(t *testing.T) {
		t.Parallel()
		reason := validateRequiredFields(EmitOptions{ScopeID: "org"})
		assert.Empty(t, reason)
	})

	t.Run("invalid capability", func(t *testing.T) {
		t.Parallel()
		reason := validateRequiredFields(EmitOptions{
			Capability: "osss",
			ScopeID:    "org",
		})
		assert.Equal(t, SkipReasonInvalidCapability, reason)
	})

	t.Run("missing scope id", func(t *testing.T) {
		t.Parallel()
		reason := validateRequiredFields(EmitOptions{Capability: CapabilityOSS})
		assert.Equal(t, SkipReasonMissingScopeID, reason)
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		reason := validateRequiredFields(EmitOptions{
			Capability: CapabilityOSS,
			ScopeID:    "org",
		})
		assert.Empty(t, reason)
	})
}
