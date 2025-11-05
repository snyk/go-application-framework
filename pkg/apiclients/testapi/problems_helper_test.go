package testapi

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProblem_GetID(t *testing.T) {
	t.Run("extracts ID from CVE problem", func(t *testing.T) {
		problemJSON := `{"id": "CVE-2021-1234", "source": "cve"}`
		var problem Problem
		err := json.Unmarshal([]byte(problemJSON), &problem)
		require.NoError(t, err)

		id := problem.GetID()
		assert.Equal(t, "CVE-2021-1234", id)
		assert.True(t, problem.HasID())
	})

	t.Run("extracts ID from CWE problem", func(t *testing.T) {
		problemJSON := `{"id": "CWE-89", "source": "cwe"}`
		var problem Problem
		err := json.Unmarshal([]byte(problemJSON), &problem)
		require.NoError(t, err)

		id := problem.GetID()
		assert.Equal(t, "CWE-89", id)
		assert.True(t, problem.HasID())
	})

	t.Run("extracts ID from snyk_vuln problem", func(t *testing.T) {
		problemJSON := `{
			"id": "SNYK-JS-LODASH-590103",
			"source": "snyk_vuln",
			"severity": "high",
			"package_name": "lodash",
			"package_version": "4.17.15"
		}`
		var problem Problem
		err := json.Unmarshal([]byte(problemJSON), &problem)
		require.NoError(t, err)

		id := problem.GetID()
		assert.Equal(t, "SNYK-JS-LODASH-590103", id)
		assert.True(t, problem.HasID())
	})

	t.Run("returns empty string for problem without ID", func(t *testing.T) {
		problemJSON := `{"source": "other"}`
		var problem Problem
		err := json.Unmarshal([]byte(problemJSON), &problem)
		require.NoError(t, err)

		id := problem.GetID()
		assert.Equal(t, "", id)
		assert.False(t, problem.HasID())
	})

	t.Run("returns empty string for invalid JSON", func(t *testing.T) {
		var problem Problem
		problem.union = []byte("invalid json")

		id := problem.GetID()
		assert.Equal(t, "", id)
		assert.False(t, problem.HasID())
	})
}
