package entitlements_service_test

import (
	"net/http"
	"net/http/httptest"
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

func TestNewIngestClient_PreservesURLPathPrefix(t *testing.T) {
	t.Parallel()

	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	client, err := entitlements_service.NewIngestClient(server.Client(), server.URL+"/v1")
	require.NoError(t, err)

	_, err = client.CreateContributingDevs(
		t.Context(),
		"11111111-1111-1111-1111-111111111111",
		"",
		entitlements_service.IngestRequest{},
	)
	require.NoError(t, err)
	assert.Equal(t, "/v1/hidden/orgs/11111111-1111-1111-1111-111111111111/contributing_devs", gotPath)
}
