package entitlements_service_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	entitlements_service "github.com/snyk/go-application-framework/pkg/apiclients/entitlements_service"
)

func TestNewIngestClient(t *testing.T) {
	t.Parallel()

	client, err := entitlements_service.NewIngestClient(nil, "https://api.snyk.io")
	require.NoError(t, err)
	require.NotNil(t, client)

	t.Run("invalid URL", func(t *testing.T) {
		t.Parallel()

		_, err := entitlements_service.NewIngestClient(nil, "://bad")
		assert.Error(t, err)
	})
}
