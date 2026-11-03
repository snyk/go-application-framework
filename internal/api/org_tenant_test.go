package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/api"
)

const (
	orgTenantOrgID    = "3c1d9e2a-7b4f-4a6e-8d0c-5f1e2a3b4c5d"
	orgTenantTenantID = "b2e4f6a8-1c3d-4e5f-9a7b-0c2d4e6f8a1b"
)

const orgWithTenantBody = `{
  "jsonapi": {"version": "1.0"},
  "data": {
    "id": "3c1d9e2a-7b4f-4a6e-8d0c-5f1e2a3b4c5d",
    "type": "org",
    "attributes": {"name": "My Org", "slug": "my-org", "is_personal": false},
    "relationships": {
      "tenant": {"data": {"id": "b2e4f6a8-1c3d-4e5f-9a7b-0c2d4e6f8a1b", "type": "tenant"}}
    }
  }
}`

func newOrgServer(t *testing.T, status int, body string) (*httptest.Server, *[]string) {
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

func Test_GetTenantIdFromOrgId_ReturnsTheTenantOfTheOrg(t *testing.T) {
	server, requests := newOrgServer(t, http.StatusOK, orgWithTenantBody)

	tenantID, err := api.NewApi(server.URL, server.Client()).GetTenantIdFromOrgId(t.Context(), orgTenantOrgID)

	require.NoError(t, err)
	assert.Equal(t, orgTenantTenantID, tenantID)
	assert.Equal(t, []string{"GET /rest/orgs/" + orgTenantOrgID + "?expand=tenant&version=2024-03-12"}, *requests)
}

func Test_GetTenantIdFromOrgId_FailsWhenTheOrgNamesNoTenant(t *testing.T) {
	server, _ := newOrgServer(t, http.StatusOK, `{"data":{"id":"`+orgTenantOrgID+`","type":"org","attributes":{"slug":"my-org"}}}`)

	tenantID, err := api.NewApi(server.URL, server.Client()).GetTenantIdFromOrgId(t.Context(), orgTenantOrgID)

	assert.Error(t, err)
	assert.Empty(t, tenantID)
}

func Test_GetTenantIdFromOrgId_FailsWhenTheApiRejectsTheRequest(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server, _ := newOrgServer(t, status, `{"jsonapi":{"version":"1.0"},"errors":[{"status":"`+http.StatusText(status)+`","detail":"rejected"}]}`)

			tenantID, err := api.NewApi(server.URL, server.Client()).GetTenantIdFromOrgId(t.Context(), orgTenantOrgID)

			assert.Error(t, err)
			assert.Empty(t, tenantID)
		})
	}
}

func Test_GetTenantIdFromOrgId_FailsOnAMalformedBody(t *testing.T) {
	server, _ := newOrgServer(t, http.StatusOK, `{"data":`)

	tenantID, err := api.NewApi(server.URL, server.Client()).GetTenantIdFromOrgId(t.Context(), orgTenantOrgID)

	assert.Error(t, err)
	assert.Empty(t, tenantID)
}

func Test_GetTenantIdFromOrgId_FailsWhenTheApiIsUnreachable(t *testing.T) {
	server, _ := newOrgServer(t, http.StatusOK, orgWithTenantBody)
	server.Close()

	tenantID, err := api.NewApi(server.URL, server.Client()).GetTenantIdFromOrgId(t.Context(), orgTenantOrgID)

	assert.Error(t, err)
	assert.Empty(t, tenantID)
}
