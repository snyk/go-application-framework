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

func TestContributorsEntityID_DefaultsToProject(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "project:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", contributorsEntityID(BillingItem{
		EntityID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	}))
}

func TestContributorsEntityID_UsesExplicitEntityType(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "target:cccccccc-cccc-4ccc-8ccc-cccccccccccc", contributorsEntityID(BillingItem{
		EntityID:   "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		EntityType: EntityTypeTarget,
	}))
}

func TestCloneItems(t *testing.T) {
	t.Parallel()

	original := []BillingItem{
		{
			EntityID:   "project-a",
			EntityType: EntityTypeTarget,
			RepoPath:   "repo-a",
			Contributors: []Contributor{
				{Email: "dev@example.com", LatestCommitDate: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
		},
	}

	cloned := cloneItems(original)
	require.Len(t, cloned, 1)

	original[0].EntityID = "mutated"
	original[0].EntityType = EntityTypeProject
	original[0].RepoPath = "mutated-repo"
	original[0].Contributors[0].Email = "mutated@example.com"

	assert.Equal(t, "project-a", cloned[0].EntityID)
	assert.Equal(t, EntityTypeTarget, cloned[0].EntityType)
	assert.True(t, filepath.IsAbs(cloned[0].RepoPath))
	assert.Contains(t, cloned[0].RepoPath, "repo-a")
	assert.Equal(t, "dev@example.com", cloned[0].Contributors[0].Email)
}

func TestFilterItems(t *testing.T) {
	t.Parallel()

	t.Run("empty input", func(t *testing.T) {
		t.Parallel()
		items, reason := filterItems(nil)
		assert.Empty(t, items)
		assert.Equal(t, SkipReasonEmptyItems, reason)
	})

	t.Run("all missing target id", func(t *testing.T) {
		t.Parallel()
		items, reason := filterItems([]BillingItem{{EntityID: ""}, {EntityID: "  "}})
		assert.Empty(t, items)
		assert.Equal(t, SkipReasonMissingEntityID, reason)
	})

	t.Run("keeps valid items", func(t *testing.T) {
		t.Parallel()
		items, reason := filterItems([]BillingItem{
			{EntityID: ""},
			{EntityID: "project-a"},
		})
		require.Len(t, items, 1)
		assert.Equal(t, "project-a", items[0].EntityID)
		assert.Empty(t, reason)
	})

	t.Run("trims target id", func(t *testing.T) {
		t.Parallel()
		items, reason := filterItems([]BillingItem{
			{EntityID: "  project-a  "},
		})
		require.Len(t, items, 1)
		assert.Equal(t, "project-a", items[0].EntityID)
		assert.Empty(t, reason)
	})
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
