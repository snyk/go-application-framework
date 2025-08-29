package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/snyk/go-application-framework/internal/api/contract"
	"github.com/snyk/go-application-framework/internal/constants"

	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow/sast_contract"
)

//go:generate go tool github.com/golang/mock/mockgen -source=api.go -destination ../mocks/api.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/api/

type ApiClient interface {
	GetDefaultOrgId() (orgID string, err error)
	GetOrgIdFromSlug(slugName string) (string, error)
	GetSlugFromOrgId(orgID string) (string, error)
	GetOrganizations(limit int) (*contract.OrganizationsResponse, error)
	Init(url string, client *http.Client)
	GetFeatureFlag(flagname string, origId string) (bool, error)
	GetUserMe() (string, error)
	GetSelf() (contract.SelfResponse, error)
	GetSastSettings(orgId string) (*sast_contract.SastResponse, error)
	GetOrgSettings(orgId string) (*contract.OrgSettingsResponse, error)
}

var _ ApiClient = (*snykApiClient)(nil)

type snykApiClient struct {
	url    string
	client *http.Client
}

// GetSlugFromOrgId retrieves the organization slug associated with a given Snyk organization ID.
//
// Parameters:
//   - orgID (string): The UUID of the organization.
//
// Returns:
//   - The organization slug as a string.
//   - An error object (if the organization is not found, or if API request or response
//     parsing errors occur).
func (a *snykApiClient) GetSlugFromOrgId(orgID string) (string, error) {
	endpoint := "/rest/orgs/" + orgID
	version := "2024-03-12"

	body, err := clientGet(a, endpoint, &version)
	if err != nil {
		return "", err
	}

	var response contract.GetOrganizationResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return "", err
	}

	return response.Data.Attributes.Slug, nil
}

// GetOrgIdFromSlug retrieves the organization ID associated with a given Snyk organization slug.
//
// Parameters:
//   - slugName (string): The unique slug identifier of the organization.
//
// Returns:
//   - The organization ID as a string.
//   - An error object (if the organization is not found, or if API request or response
//     parsing errors occur).
func (a *snykApiClient) GetOrgIdFromSlug(slugName string) (string, error) {
	endpoint := "/rest/orgs"
	version := "2024-03-12"

	body, err := clientGet(a, endpoint, &version, "slug", slugName)
	if err != nil {
		return "", err
	}

	var response contract.OrganizationsResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return "", err
	}

	organizations := response.Organizations
	for _, organization := range organizations {
		if organization.Attributes.Slug == slugName {
			return organization.Id, nil
		}
	}
	return "", fmt.Errorf("org ID not found for slug %v", slugName)
}

// GetOrganizations retrieves organizations accessible to the authenticated user.
//
// Parameters:
//   - limit: Maximum number of organizations to return
//
// Returns:
//   - A pointer to OrganizationsResponse containing organizations.
//   - An error object (if an error occurred during the API request or response parsing).
func (a *snykApiClient) GetOrganizations(limit int) (*contract.OrganizationsResponse, error) {
	endpoint := "/rest/orgs"
	version := "2024-10-15"

	body, err := clientGet(a, endpoint, &version, "limit", fmt.Sprintf("%d", limit))
	if err != nil {
		return nil, err
	}

	var response contract.OrganizationsResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}

	return &response, nil
}

// GetDefaultOrgId retrieves the default organization ID associated with the authenticated user.
//
// Returns:
//   - The user's default organization ID as a string.
//   - An error object (if an error occurred while fetching user data).
func (a *snykApiClient) GetDefaultOrgId() (string, error) {
	selfData, err := a.GetSelf()
	if err != nil {
		return "", fmt.Errorf("unable to retrieve org ID: %w", err)
	}

	return selfData.Data.Attributes.DefaultOrgContext, nil
}

// GetUserMe retrieves the username for the authenticated user from the Snyk API.
//
// Returns:
//   - The authenticated user's username as a string.
//   - An error object (if an error occurred while fetching user data or extracting the username).
func (a *snykApiClient) GetUserMe() (string, error) {
	selfData, err := a.GetSelf()
	if err != nil {
		return "", fmt.Errorf("error while fetching self data: %w", err) // Prioritize error
	}

	// according to API spec for get /self
	// username is not a mandatory field, only name and email
	// service accounts contain only name (name of the service account token) and org_context uuid
	// spec: https://apidocs.snyk.io/?version=2024-04-29#get-/self
	if selfData.Data.Attributes.Username != "" {
		return selfData.Data.Attributes.Username, nil
	}

	if selfData.Data.Attributes.Name != "" {
		return selfData.Data.Attributes.Name, nil
	}

	return "", fmt.Errorf("error while extracting user: missing properties username/name")
}

// GetFeatureFlag determines the state of a feature flag for the specified organization.
//
// Parameters:
//   - flagname (string): The name of the feature flag to check.
//   - orgId (string): The ID of the organization associated with the feature flag.
//
// Returns:
//   - A boolean indicating if the feature flag is enabled (true) or disabled (false).
//   - An error object (if an error occurred during the API request, response parsing,
//     or if the organization ID is invalid).
func (a *snykApiClient) GetFeatureFlag(flagname string, orgId string) (bool, error) {
	const defaultResult = false

	u := a.url + "/v1/cli-config/feature-flags/" + flagname + "?org=" + orgId

	if len(orgId) <= 0 {
		return defaultResult, fmt.Errorf("failed to lookup feature flag with orgiId not set")
	}

	res, err := a.client.Get(u)
	if err != nil {
		return defaultResult, fmt.Errorf("unable to retrieve feature flag: %w", err)
	}
	//goland:noinspection GoUnhandledErrorResult
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return defaultResult, fmt.Errorf("unable to retrieve feature flag: %w", err)
	}

	var flag contract.OrgFeatureFlagResponse
	flag.Ok = defaultResult
	if err = json.Unmarshal(body, &flag); err != nil {
		return defaultResult, fmt.Errorf("unable to retrieve feature flag (status: %d): %w", res.StatusCode, err)
	}

	if res.StatusCode != http.StatusOK || flag.Code == http.StatusUnauthorized || flag.Code == http.StatusForbidden {
		return defaultResult, err
	}

	return flag.Ok, nil
}

// GetSelf retrieves the authenticated user's information from the Snyk API.
//
// Returns:
//   - A `contract.SelfResponse` struct containing the user's data.
//   - An error object (if an error occurred during the API request or response parsing).
func (a *snykApiClient) GetSelf() (contract.SelfResponse, error) {
	endpoint := "/rest/self"
	var selfData contract.SelfResponse

	body, err := clientGet(a, endpoint, nil)
	if err != nil {
		return selfData, err
	}

	if err = json.Unmarshal(body, &selfData); err != nil {
		return selfData, fmt.Errorf("unable to retrieve self data: %w", err)
	}

	return selfData, nil
}

func (a *snykApiClient) GetSastSettings(orgId string) (*sast_contract.SastResponse, error) {
	endpoint := a.url + "/v1/cli-config/settings/sast?org=" + url.QueryEscape(orgId)
	res, err := a.client.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve settings: %w", err)
	}
	//goland:noinspection GoUnhandledErrorResult
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve settings: %w", err)
	}

	var response sast_contract.SastResponse
	if err = json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("unable to retrieve settings (status: %d): %w", res.StatusCode, err)
	}

	return &response, err
}

func (a *snykApiClient) GetOrgSettings(orgId string) (*contract.OrgSettingsResponse, error) {
	endpoint := fmt.Sprintf("%s/v1/org/%s/settings", a.url, url.QueryEscape(orgId))

	res, err := a.client.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve org settings: %w", err)
	}
	//goland:noinspection GoUnhandledErrorResult
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve org settings: %w", err)
	}

	var response contract.OrgSettingsResponse
	if err = json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("unable to retrieve org settings (status: %d): %w", res.StatusCode, err)
	}

	return &response, err
}

// clientGet performs an HTTP GET request to the Snyk API, handling query parameters,
// API versioning, and basic error checking.
//
// Parameters:
//   - a (snykApiClient): A reference to the Snyk API client object.
//   - endpoint (string): The endpoint path to be appended to the API base URL.
//   - version (*string):  An optional pointer to a string specifying the desired API version.
//     If nil or an empty string, the default API version is used.
//   - queryParams (...string): A variable number of string arguments representing key-value
//     pairs for additional query parameters. Parameters are expected
//     in the format "key1", "value1", "key2", "value2", etc.
//
// Returns:
//   - The raw response body as a byte slice ([]byte).
//   - An error object (if an error occurred during the request or response handling).
//
// Example:
// apiVersion := "2022-01-12"
// response, err := clientGet(myApiClient, "/organizations", &apiVersion, "limit", "50")
func clientGet(a *snykApiClient, endpoint string, version *string, queryParams ...string) ([]byte, error) {
	var apiVersion string = constants.SNYK_DEFAULT_API_VERSION
	if version != nil && *version != "" {
		apiVersion = *version
	}

	queryParams = append(queryParams, "version", apiVersion)
	url, err := BuildUrl(a, endpoint, queryParams...)
	if err != nil {
		return nil, err
	}

	res, err := a.client.Get(url.String())
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed (status: %d)", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	defer res.Body.Close()
	return body, nil
}

// BuildUrl constructs a URL for the Snyk API, appending query parameters from a provided slice.
//
// Parameters:
//   - a (snykApiClient): A reference to the Snyk API client object.
//   - endpoint (string): The endpoint path to be appended to the API base URL.
//   - queryParams (...string): A variable number of string arguments representing key-value pairs for the query parameters.
//     Parameters are expected in the format "key1", "value1", "key2", "value2", etc.
//
// Returns:
//   - A constructed url.URL object.
//   - An error object (if an error occurred during URL construction or parsing).
//
// Example:
//
//	url, err := BuildUrl(myApiClient, "/users", "filter", "active", "limit", "10")
//	if err != nil {
//	    // Handle error
//	}
//	// Use the constructed url object (e.g., to make an API call)
func BuildUrl(a *snykApiClient, endpoint string, queryParams ...string) (*url.URL, error) {
	u, err := url.Parse(a.url + endpoint)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	for i := 0; i < len(queryParams); i += 2 {
		key := queryParams[i]
		value := queryParams[i+1]
		q.Set(key, value)
	}

	u.RawQuery = q.Encode()
	return u, nil
}

func (a *snykApiClient) Init(url string, client *http.Client) {
	a.url = url
	a.client = client
}

func NewApi(url string, httpClient *http.Client) ApiClient {
	client := NewApiInstance()
	client.Init(url, httpClient)
	return client
}

func NewApiInstance() ApiClient {
	return &snykApiClient{}
}
