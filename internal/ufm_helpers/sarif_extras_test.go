package ufm_helpers

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeMetadata(t *testing.T) {
	extra := FindingExtra{
		MessageText: "text",
		Arguments:   []string{"a"},
		Suppression: &SuppressionExtra{GUID: "guid"},
	}

	t.Run("returns a typed value as is", func(t *testing.T) {
		decoded, err := DecodeMetadata[FindingExtra](extra)
		require.NoError(t, err)
		assert.Equal(t, extra, decoded)
	})

	t.Run("decodes the generic form left by a JSON round trip", func(t *testing.T) {
		data, err := json.Marshal(extra)
		require.NoError(t, err)
		var generic interface{}
		require.NoError(t, json.Unmarshal(data, &generic))

		decoded, err := DecodeMetadata[FindingExtra](generic)
		require.NoError(t, err)
		assert.Equal(t, extra, decoded)
	})

	t.Run("fails on a mismatching shape", func(t *testing.T) {
		_, err := DecodeMetadata[[]Coverage]([]interface{}{map[string]interface{}{"files": "not-a-number"}})
		assert.Error(t, err)
	})
}
