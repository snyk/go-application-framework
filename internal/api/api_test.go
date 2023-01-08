package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/internal/api/contract"
	"github.com/stretchr/testify/assert"
)

func Test_GetDefaultOrgId_ReturnsCorrectOrgId(t *testing.T) {
	// Arrange
	t.Parallel()
	selfResponse := newMockSelfResponse(t)
	expectedOrgId := selfResponse.Data.Attributes.DefaultOrgContext
	server := setupSingleReponseServer(t, selfResponse)
	api := api.NewApi(server.URL, http.DefaultClient)

	// Act
	orgId, err := api.GetDefaultOrgId()
	if err != nil {
		t.Error(err)
	}

	// Assert
	assert.Equal(t, expectedOrgId, orgId)
}

func Test_GetOrgIdFromSlug_ReturnsCorrectOrgId(t *testing.T) {
	// Arrange
	t.Parallel()
	orgResponse := newMockOrgResponse(t)
	server := setupSingleReponseServer(t, orgResponse)
	api := api.NewApi(server.URL, http.DefaultClient)

	for _, org := range orgResponse.Organizations {
		expectedOrgId := org.ID
		slugName := org.Slug

		// Act
		orgId, err := api.GetOrgIdFromSlug(slugName)
		if err != nil {
			t.Error(err)
		}

		// Assert
		assert.Equal(t, expectedOrgId, orgId)
	}
}

func newMockOrgResponse(t *testing.T) contract.OrganizationsResponse {
	t.Helper()

	return contract.OrganizationsResponse{
		Organizations: []contract.Organization{
			{
				Name:  "defaultOrg",
				ID:    "27ce75bf-5794-4bfd-9ae7-e779f465abdf",
				Slug:  "default-org",
				URL:   "https://api.snyk.io/org/default-org",
				Group: nil,
			},
			{
				Name: "secondOrg",
				ID:   "ebb351b1-e883-4a07-9ebb-75a7d22b56a8",
				Slug: "second-org",
				URL:  "https://api.snyk.io/org/second-org",
				Group: &contract.Group{
					Name: "ABCD INC",
					ID:   "58eec199-6ec0-4881-9d0d-9f62ebc6b6ab",
				},
			},
		},
	}
}

func setupSingleReponseServer(t *testing.T, response any) *httptest.Server {
	t.Helper()
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		t.Error(err)
	}
	handler := newHttpHandler(t, jsonResponse)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return server
}

// returns a handler that simply returns status OK and the response provided
func newHttpHandler(t *testing.T, resp []byte) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write(resp)
		if err != nil {
			t.Error(err)
		}
	}
}

func newMockSelfResponse(t *testing.T) contract.SelfResponse {
	t.Helper()
	return contract.SelfResponse{
		Data: contract.SelfResponseData{
			Type: "user",
			Id:   "2921ea23-1733-4088-8d0a-eafda90486eb",
			Attributes: contract.SelfResponseDataAttribute{
				Name:              "Testy McTestFace",
				AvatarUrl:         "https://avatars.com/testy.png",
				DefaultOrgContext: "bd9d18a2-7978-42c5-b480-c20d83776f41",
				Username:          "testy.mctestface",
				Email:             "testy.mctestface@snyk.io",
			},
		},
	}
}
