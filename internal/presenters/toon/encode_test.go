package toon_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/presenters/toon"
)

func TestEncodeJSON_contractGoldens(t *testing.T) {
	t.Parallel()

	cases := []string{
		"sca",
		"secrets",
		"empty_sca",
		"empty_secrets",
		"mixed",
		"nested",
		"no_results",
	}

	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := filepath.Join("..", "testdata", "ufm", "toon")
			jsonBytes, err := os.ReadFile(filepath.Join(dir, name+".json"))
			require.NoError(t, err)

			want, err := os.ReadFile(filepath.Join(dir, name+".toon"))
			require.NoError(t, err)

			got, err := toon.EncodeJSON(jsonBytes)
			require.NoError(t, err)
			assert.Equal(t, string(want), string(got))
		})
	}
}
