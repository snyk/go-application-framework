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

	scopeID := "11111111-1111-1111-1111-111111111111"
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

	items := []BillingItem{
		{TargetID: "22222222-2222-2222-2222-222222222222", Contributors: contributors},
		{TargetID: "33333333-3333-3333-3333-333333333333", Contributors: contributors},
	}

	body, err := marshalIngestPayload(CapabilityOSS, scopeID, items, nil)
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

	items := []BillingItem{
		{
			TargetID: "project-a",
			Contributors: []Contributor{
				{Email: "valid@example.com", LatestCommitDate: time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)},
				{Email: "invalid@example.com"},
			},
		},
	}

	body, err := marshalIngestPayload(CapabilityOSS, "org-uuid", items, nil)
	require.NoError(t, err)

	var got map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &got))

	payloadItems, ok := got["items"].([]interface{})
	require.True(t, ok)
	require.Len(t, payloadItems, 1)

	firstItem, ok := payloadItems[0].(map[string]interface{})
	require.True(t, ok)
	contributors, ok := firstItem["contributors"].([]interface{})
	require.True(t, ok)
	require.Len(t, contributors, 1)

	contributor, ok := contributors[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "valid@example.com", contributor["email"])
	assert.Equal(t, "2026-01-15T12:00:00Z", contributor["latest_commit_date"])
}

func TestCloneItems(t *testing.T) {
	t.Parallel()

	original := []BillingItem{
		{
			TargetID: "project-a",
			RepoPath: "repo-a",
			Contributors: []Contributor{
				{Email: "dev@example.com", LatestCommitDate: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
		},
	}

	cloned := cloneItems(original)
	require.Len(t, cloned, 1)

	original[0].TargetID = "mutated"
	original[0].RepoPath = "mutated-repo"
	original[0].Contributors[0].Email = "mutated@example.com"

	assert.Equal(t, "project-a", cloned[0].TargetID)
	assert.Equal(t, "repo-a", cloned[0].RepoPath)
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
		items, reason := filterItems([]BillingItem{{TargetID: ""}, {TargetID: "  "}})
		assert.Empty(t, items)
		assert.Equal(t, SkipReasonMissingTargetID, reason)
	})

	t.Run("keeps valid items", func(t *testing.T) {
		t.Parallel()
		items, reason := filterItems([]BillingItem{
			{TargetID: ""},
			{TargetID: "project-a"},
		})
		require.Len(t, items, 1)
		assert.Equal(t, "project-a", items[0].TargetID)
		assert.Empty(t, reason)
	})

	t.Run("trims target id", func(t *testing.T) {
		t.Parallel()
		items, reason := filterItems([]BillingItem{
			{TargetID: "  project-a  "},
		})
		require.Len(t, items, 1)
		assert.Equal(t, "project-a", items[0].TargetID)
		assert.Empty(t, reason)
	})
}

func TestValidateRequiredFields(t *testing.T) {
	t.Parallel()

	t.Run("missing capability", func(t *testing.T) {
		t.Parallel()
		reason := validateRequiredFields(EmitOptions{ScopeID: "org"})
		assert.Equal(t, SkipReasonMissingCapability, reason)
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
