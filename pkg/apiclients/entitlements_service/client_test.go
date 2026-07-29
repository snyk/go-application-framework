package entitlements_service_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	entitlements_service "github.com/snyk/go-application-framework/pkg/apiclients/entitlements_service"
)

func TestIngestServerURL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		ingestURL string
	}{
		{
			name:      "host only",
			ingestURL: "https://api.snyk.io",
		},
		{
			name:      "full ingest URL",
			ingestURL: "https://api.snyk.io" + entitlements_service.IngestPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client, err := entitlements_service.NewIngestClient(nil, tt.ingestURL)
			require.NoError(t, err)
			require.NotNil(t, client)
		})
	}

	t.Run("invalid URL", func(t *testing.T) {
		t.Parallel()

		_, err := entitlements_service.NewIngestClient(nil, "://bad")
		assert.Error(t, err)
	})
}
