package api

//go:generate $GOPATH/bin/mockgen -source=api.go -destination ../mocks/api.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/api/

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/snyk/go-application-framework/internal/api/contract"
	"github.com/snyk/go-application-framework/internal/constants"
)

type ApiClient interface {
	GetDefaultOrgId() (orgID string, err error)
	GetOrgIdFromSlug(slugName string) (string, error)
	GetSlugFromOrgId(orgId string) (string, error)
	Init(url string, client *http.Client)
}

type snykApiClient struct {
	url    string
	client *http.Client
}

func (a *snykApiClient) GetOrgIdFromSlug(slugName string) (string, error) {
	url := a.url + "/v1/orgs"
	res, err := a.client.Get(url)
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	var userOrgInfo contract.OrganizationsResponse
	err = json.Unmarshal(body, &userOrgInfo)
	if err != nil {
		return "", err
	}

	for _, org := range userOrgInfo.Organizations {
		if org.Slug == slugName {
			return org.ID, nil
		}
	}

	return "", fmt.Errorf("org ID not found for slug %v", slugName)
}

func (a *snykApiClient) GetSlugFromOrgId(orgId string) (string, error) {
	url := a.url + "/rest/orgs/" + orgId + "?version=" + constants.SNYK_API_VERSION
	res, err := a.client.Get(url)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve org slugname: %w", err)
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve org slugname: %w", err)
	}

	if res.StatusCode != 200 {
		return "", fmt.Errorf("unable to retrieve org slugname (status: %d)", res.StatusCode)
	}

	var restApiOrgInfo contract.RestApiOrganizationsResponse
	err = json.Unmarshal(body, &restApiOrgInfo)
	if err != nil {
		return "", err
	}

	return restApiOrgInfo.Data.Attributes.Slug, nil
}

func (a *snykApiClient) GetDefaultOrgId() (string, error) {
	url := a.url + "/rest/self?version=" + constants.SNYK_API_VERSION
	res, err := a.client.Get(url)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve org ID: %w", err)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve org ID: %w", err)
	}

	if res.StatusCode != 200 {
		return "", fmt.Errorf("unable to retrieve org ID (status: %d)", res.StatusCode)
	}

	var userInfo contract.SelfResponse
	if err = json.Unmarshal(body, &userInfo); err != nil {
		return "", fmt.Errorf("unable to retrieve org ID (status: %d): %w", res.StatusCode, err)
	}

	return userInfo.Data.Attributes.DefaultOrgContext, nil
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
