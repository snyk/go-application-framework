package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/snyk/go-application-framework/internal/constants"
)

type selfDocument struct {
	Data struct {
		Attributes struct {
			AvatarUrl         string `json:"avatar_url,omitempty"`
			DefaultOrgContext string `json:"default_org_context,omitempty"`
			Name              string `json:"name,omitempty"`
			Username          string `json:"username,omitempty"`
		} `json:"attributes,omitempty"`
		Id   string `json:"id,omitempty"`
		Type string `json:"type,omitempty"`
	}
}

func GetDefaultOrgID(client *http.Client, apiUrl string) (orgID string, err error) {
	url := apiUrl + "/rest/self?version=" + constants.SNYK_API_VERSION
	res, err := client.Get(url)
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

	var userInfo selfDocument
	if err = json.Unmarshal(body, &userInfo); err != nil {
		return "", fmt.Errorf("unable to retrieve org ID (status: %d): %w", res.StatusCode, err)
	}

	orgID = userInfo.Data.Attributes.DefaultOrgContext
	return orgID, nil
}
