package api

//go:generate $GOPATH/bin/mockgen -source=api.go -destination ../mocks/api.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/api/

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/snyk/go-application-framework/internal/api/contract"
	"github.com/snyk/go-application-framework/internal/constants"
)

type ApiClient interface {
	GetDefaultOrgId() (orgID string, err error)
	GetOrgIdFromSlug(slugName string) (string, error)
	Init(url string, client *http.Client)
	GetFeatureFlag(flagname string, origId string) (bool, error)
}

type snykApiClient struct {
	url    string
	client *http.Client
}

func (a *snykApiClient) GetOrgIdFromSlug(slugName string) (string, error) {
	u, err := OrgsApiURL(a.url, slugName)
	if err != nil {
		return "", err
	}

	res, err := a.client.Get(u.String())
	if err != nil {
		return "", err
	}

	//goland:noinspection GoUnhandledErrorResult
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
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

func OrgsApiURL(baseURL, slugName string) (*url.URL, error) {
	u, err := url.Parse(baseURL + "/rest/orgs")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("version", "2024-03-12") // use a constant for the orgs API
	q.Set("slug", slugName)
	u.RawQuery = q.Encode()
	return u, nil
}

func (a *snykApiClient) GetDefaultOrgId() (string, error) {
	u := a.url + "/rest/self?version=" + constants.SNYK_API_VERSION
	res, err := a.client.Get(u)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve org ID: %w", err)
	}
	//goland:noinspection GoUnhandledErrorResult
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve org ID: %w", err)
	}

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unable to retrieve org ID (status: %d)", res.StatusCode)
	}

	var userInfo contract.SelfResponse
	if err = json.Unmarshal(body, &userInfo); err != nil {
		return "", fmt.Errorf("unable to retrieve org ID (status: %d): %w", res.StatusCode, err)
	}

	return userInfo.Data.Attributes.DefaultOrgContext, nil
}

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
	if err = json.Unmarshal(body, &flag); err != nil {
		return defaultResult, fmt.Errorf("unable to retrieve feature flag (status: %d): %w", res.StatusCode, err)
	}

	if res.StatusCode != http.StatusOK || flag.Code == http.StatusUnauthorized || flag.Code == http.StatusForbidden {
		return defaultResult, err
	}

	return true, nil
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
