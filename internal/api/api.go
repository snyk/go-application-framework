package api

//go:generate $GOPATH/bin/mockgen -source=api.go -destination ../mocks/api.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/api/

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/snyk/go-application-framework/internal/api/contract"
	"github.com/snyk/go-application-framework/internal/constants"
)

type ApiClient interface {
	GetDefaultOrgId() (orgID string, err error)
	GetOrgIdFromSlug(slugName string) (string, error)
	SetUrl(url string)
	SetClient(client *http.Client)
}

type snykApiClient struct {
	url    string
	client *http.Client
}

func (a *snykApiClient) GetOrgIdFromSlug(slugName string) (string, error) {
	url := a.url + "/api/v1/orgs"
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

	return "", errors.New(fmt.Sprintf("org ID not found for slug %v", slugName))
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

func (a *snykApiClient) SetUrl(url string) {
	a.url = url
}

func (a *snykApiClient) SetClient(client *http.Client) {
	a.client = client
}

func NewApi(url string, httpClient *http.Client) ApiClient {
	return &snykApiClient{url, httpClient}
}

func NewApiInstance() ApiClient {
	return &snykApiClient{}
}
