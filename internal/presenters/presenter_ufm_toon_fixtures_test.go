package presenters_test

import (
	"context"
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

			findings, ok, err := results[0].Findings(context.Background())
			require.NoError(t, err)
			assert.True(t, ok)
			assert.NotEmpty(t, findings)
		})
	}
}
