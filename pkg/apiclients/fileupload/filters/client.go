package filters

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

// AllowList represents the response structure from the deeproxy filters API.
type AllowList struct {
	ConfigFiles []string `json:"configFiles"`
	Extensions  []string `json:"extensions"`
}

// Client defines the interface for the filters client.
type Client interface {
	GetFilters(ctx context.Context, orgID uuid.UUID) (AllowList, error)
}

// DeeproxyClient is the deeproxy implementation of the Client interface.
type DeeproxyClient struct {
	httpClient *http.Client
	cfg        Config
}

// Config contains the configuration for the filters client.
type Config struct {
	BaseURL   string
	IsFedRamp bool
}

var _ Client = (*DeeproxyClient)(nil)

// NewDeeproxyClient creates a new DeeproxyClient with the given configuration and options.
func NewDeeproxyClient(cfg Config, opts ...Opt) *DeeproxyClient {
	c := &DeeproxyClient{
		cfg:        cfg,
		httpClient: http.DefaultClient,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// GetFilters returns the deeproxy filters in the form of an AllowList.
func (c *DeeproxyClient) GetFilters(ctx context.Context, orgID uuid.UUID) (AllowList, error) {
	var allowList AllowList

	url := getFilterURL(c.cfg.BaseURL, orgID, c.cfg.IsFedRamp)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return allowList, fmt.Errorf("failed to create deeproxy filters request: %w", err)
	}

	req.Header.Set("snyk-org-name", orgID.String())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return allowList, fmt.Errorf("error making deeproxy filters request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return allowList, fmt.Errorf("unexpected response code: %s", resp.Status)
	}

	if err := json.NewDecoder(resp.Body).Decode(&allowList); err != nil {
		return allowList, fmt.Errorf("failed to decode deeproxy filters response: %w", err)
	}

	return allowList, nil
}
