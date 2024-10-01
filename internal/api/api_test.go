package api_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pkg/errors"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/internal/api/contract"
	"github.com/snyk/go-application-framework/internal/constants"
)

func Test_GetDefaultOrgId_ReturnsCorrectOrgId(t *testing.T) {
	// Arrange
	t.Parallel()
	selfResponse := newMockSelfResponse(t)
	expectedOrgId := selfResponse.Data.Attributes.DefaultOrgContext
	server := setupSingleReponseServer(t, "/rest/self?version="+constants.SNYK_DEFAULT_API_VERSION, selfResponse)
	client := api.NewApi(server.URL, http.DefaultClient)

	// Act
	orgId, err := client.GetDefaultOrgId()
	if err != nil {
		t.Error(err)
	}

	// Assert
	assert.Equal(t, expectedOrgId, orgId)
}

func Test_GetSlugFromOrgId_ReturnsCorrectSlug(t *testing.T) {
	// Arrange
	t.Parallel()
	slugResponse := newMockOrgSlugResponse(t)
	orgID := slugResponse.Data.Id
	expectedSlug := slugResponse.Data.Attributes.Slug
	u := fmt.Sprintf("/rest/orgs/%s?version=2024-03-12", orgID)

	server := setupSingleReponseServer(t, u, slugResponse)
	client := api.NewApi(server.URL, http.DefaultClient)

	// Act
	actualSlug, err := client.GetSlugFromOrgId(orgID)
	if err != nil {
		t.Error(err)
	}

	// Assert
	assert.Equal(t, expectedSlug, actualSlug)
}

func Test_GetOrgIdFromSlug_ReturnsCorrectOrgId(t *testing.T) {
	// Arrange
	t.Parallel()
	orgResponse := newMockOrgResponse(t)

	for _, org := range orgResponse.Organizations {
		slugName := org.Attributes.Slug
		expectedOrgId := org.Id
		u := fmt.Sprintf("/rest/orgs?slug=%s&version=2024-03-12", slugName)

		server := setupSingleReponseServer(t, u, orgResponse)
		apiClient := api.NewApi(server.URL, http.DefaultClient)

		// Act
		orgId, err := apiClient.GetOrgIdFromSlug(slugName)
		if err != nil {
			t.Error(err)
		}

		// Assert
		assert.Equal(t, expectedOrgId, orgId)
	}
}

func Test_GetFeatureFlag_false(t *testing.T) {
	// Arrange
	t.Parallel()

	org := "myOrg"
	featureFlagName := "myFlag"
	featureFlagResponse := contract.OrgFeatureFlagResponse{
		Code: http.StatusForbidden,
	}
	server := setupSingleReponseServer(t, "/v1/cli-config/feature-flags/"+featureFlagName+"?org="+org, featureFlagResponse)
	client := api.NewApi(server.URL, http.DefaultClient)

	actual, err := client.GetFeatureFlag(featureFlagName, org)
	assert.NoError(t, err)
	assert.False(t, actual)

	actual, err = client.GetFeatureFlag("unknownFF", org)
	assert.Error(t, err)
	assert.False(t, actual)
}

func Test_GetFeatureFlag_true(t *testing.T) {
	// Arrange
	t.Parallel()

	org := "myOrg"
	featureFlagName := "myFlag"
	featureFlagResponse := contract.OrgFeatureFlagResponse{
		Ok:   true,
		Code: http.StatusOK,
	}
	server := setupSingleReponseServer(t, "/v1/cli-config/feature-flags/"+featureFlagName+"?org="+org, featureFlagResponse)
	client := api.NewApi(server.URL, http.DefaultClient)

	actual, err := client.GetFeatureFlag(featureFlagName, org)
	assert.NoError(t, err)
	assert.True(t, actual)
}

func newMockOrgSlugResponse(t *testing.T) contract.GetOrganizationResponse {
	t.Helper()
	slugJson := `
				{
				  "data": {
					"id": "be9221c6-5f63-4339-a07e-43d38b3ecb8b",
					"type": "org",
					"attributes": {
					  "group_id": "b2374863-df81-46ba-85e2-d76b2b8dac4f",
					  "is_personal": false,
					  "name": "platform_hammerhead_testing",
					  "slug": "platform_hammerhead_testing",
					  "created_at": "2023-06-09T10:37:07Z",
					  "updated_at": "2024-03-22T10:46:32Z"
					}
				  },
				  "jsonapi": {
					"version": "1.0"
				  },
				  "links": {
					"self": "/rest/orgs/be9221c6-5f63-4339-a07e-43d38b3ecb8b?version=2023-05-29"
				  }
				}
				`
	var response contract.GetOrganizationResponse
	err := json.Unmarshal([]byte(slugJson), &response)
	if err != nil {
		t.Fatal(errors.Wrap(err, "cannot create mock response"))
	}
	return response
}

func newMockOrgResponse(t *testing.T) contract.OrganizationsResponse {
	t.Helper()
	orgJson := `
				{
					"data": [
						{
							"id": "27ce75bf-5794-4bfd-9ae7-e779f465abdf",
							"type": "org",
							"attributes": {
								"is_personal": true,
								"name": "defaultOrg",
								"slug": "default-org"
							}
						},
						{
							"id": "ebb351b1-e883-4a07-9ebb-75a7d22b56a8",
							"type": "org",
							"attributes": {
								"is_personal": true,
								"name": "secondOrg",
								"slug": "second-org",
								"groupId": "58eec199-6ec0-4881-9d0d-9f62ebc6b6ab"
							}
						}
					],
					"jsonapi": {
						"version": "1.0"
					},
					"links": {
						"self": "/rest/orgs?version=2024-04-11",
						"first": "/rest/orgs?version=2024-04-11"
					}
				}
				`
	var response contract.OrganizationsResponse
	err := json.Unmarshal([]byte(orgJson), &response)
	if err != nil {
		t.Fatal(errors.Wrap(err, "cannot create mock response"))
	}
	return response
}

func setupSingleReponseServer(t *testing.T, url string, response any) *httptest.Server {
	t.Helper()
	jsonResponse, err := json.Marshal(response)
	if err != nil {
		t.Error(err)
	}
	handler := newHttpHandler(t, url, jsonResponse)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	return server
}

// returns a handler that simply returns status OK and the response provided
func newHttpHandler(t *testing.T, url string, resp []byte) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != url {
			w.WriteHeader(http.StatusForbidden)
			return
		}

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
