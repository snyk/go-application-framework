package api

//go:generate $GOPATH/bin/mockgen -source=api.go -destination ../mocks/api.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/api/

import (
	"encoding/json"
	"fmt"
	"github.com/snyk/go-application-framework/internal/api/contract"
	"github.com/snyk/go-application-framework/internal/constants"
	"io"
	"net/http"
	url2 "net/url"
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
	apiVersion := "version=2024-03-12"
	escapedSlug := url2.PathEscape(slugName)
	url := fmt.Sprintf("%s/rest/orgs?%s&slug=%s", a.url, apiVersion, escapedSlug)

	res, err := a.client.Get(url)
	if err != nil {
		return "", err
	}
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
	if len(organizations) == 1 {
		return organizations[0].Id, nil
	}

	return "", fmt.Errorf("org ID not found for slug %v", slugName)
}

func (a *snykApiClient) GetDefaultOrgId() (string, error) {
	url := a.url + "/rest/self?version=" + constants.SNYK_API_VERSION
	res, err := a.client.Get(url)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve org ID: %w", err)
	}
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

	url := a.url + "/v1/cli-config/feature-flags/" + flagname + "?org=" + orgId

	if len(orgId) <= 0 {
		return defaultResult, fmt.Errorf("failed to lookup feature flag with orgiId not set")
	}

	res, err := a.client.Get(url)
	if err != nil {
		return defaultResult, fmt.Errorf("unable to retrieve feature flag: %w", err)
	}
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
