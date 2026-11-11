package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/api"
)

const machineSelfBody = `{
  "jsonapi": {"version": "1.0"},
  "links": {"self": "/rest/machines/self"},
  "data": {
    "id": "0f5d6c3e-2b1a-4c9d-8e7f-6a5b4c3d2e1f",
    "type": "machine",
    "attributes": {
      "tenant_id": "8f9a2c41-6b0e-4d7a-9c3e-1f2b3a4c5d6e",
      "status": "active",
      "enrolled": true,
      "enrollment_count": 1,
      "identifiers": [{"type": "serial_number", "value": "SERIAL-1"}],
      "created_at": "2025-01-01T00:00:00Z"
    }
  }
}`

func newMachineSelfServer(t *testing.T, status int, body string) (*httptest.Server, *[]string) {
	t.Helper()
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.String())
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(status)
		if _, err := w.Write([]byte(body)); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(server.Close)
	return server, &requests
}

func Test_GetMachineTenantId_ReturnsTheTenantOfTheMachinesOwnRecord(t *testing.T) {
	server, requests := newMachineSelfServer(t, http.StatusOK, machineSelfBody)

	tenantID, err := api.NewApi(server.URL, server.Client()).GetMachineTenantId(t.Context())

	require.NoError(t, err)
	assert.Equal(t, "8f9a2c41-6b0e-4d7a-9c3e-1f2b3a4c5d6e", tenantID)
	assert.Equal(t, []string{"GET /rest/machines/self?version=2024-10-15"}, *requests)
}

func Test_GetMachineTenantId_FailsWhenTheApiRejectsTheRequest(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server, _ := newMachineSelfServer(t, status, `{"jsonapi":{"version":"1.0"},"errors":[{"status":"`+http.StatusText(status)+`","detail":"rejected"}]}`)

			tenantID, err := api.NewApi(server.URL, server.Client()).GetMachineTenantId(t.Context())

			assert.Error(t, err)
			assert.Empty(t, tenantID)
		})
	}
}

func Test_GetMachineTenantId_FailsOnAMalformedBody(t *testing.T) {
	server, _ := newMachineSelfServer(t, http.StatusOK, `{"data":`)

	tenantID, err := api.NewApi(server.URL, server.Client()).GetMachineTenantId(t.Context())

	assert.Error(t, err)
	assert.Empty(t, tenantID)
}

func Test_GetMachineTenantId_FailsWhenTheRecordNamesNoTenant(t *testing.T) {
	server, _ := newMachineSelfServer(t, http.StatusOK, `{"data":{"id":"0f5d6c3e-2b1a-4c9d-8e7f-6a5b4c3d2e1f","type":"machine","attributes":{"status":"active"}}}`)

	tenantID, err := api.NewApi(server.URL, server.Client()).GetMachineTenantId(t.Context())

	assert.Error(t, err)
	assert.Empty(t, tenantID)
}

func Test_GetMachineTenantId_FailsWhenTheApiIsUnreachable(t *testing.T) {
	server, _ := newMachineSelfServer(t, http.StatusOK, machineSelfBody)
	server.Close()

	tenantID, err := api.NewApi(server.URL, server.Client()).GetMachineTenantId(t.Context())

	assert.Error(t, err)
	assert.Empty(t, tenantID)
}
