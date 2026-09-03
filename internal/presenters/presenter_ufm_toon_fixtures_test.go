package presenters_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/utils/ufm"
)

func Test_TOONFixtures_Parse(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"testdata/ufm/sca.toon.testresult.json",
		"testdata/ufm/secrets.toon.testresult.json",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			raw, err := os.ReadFile(path)
			require.NoError(t, err)

			results, err := ufm.NewSerializableTestResultFromBytes(raw)
			require.NoError(t, err)
			require.NotEmpty(t, results)

			findings, ok, err := results[0].Findings(nil)
			require.NoError(t, err)
			assert.True(t, ok)
			assert.NotEmpty(t, findings)
		})
	}
}

func Test_TOONFixtures_GoldensExist(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"testdata/ufm/toon/sca.concise.toon",
		"testdata/ufm/toon/sca.concise-empty.toon",
		"testdata/ufm/toon/secrets.concise.toon",
		"testdata/ufm/toon/secrets.concise-empty.toon",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			_, err := os.ReadFile(path)
			require.NoError(t, err)
		})
	}
}
