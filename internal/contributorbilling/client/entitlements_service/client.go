package entitlements_service

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"

	v20260729 "github.com/snyk/go-application-framework/internal/contributorbilling/client/entitlements_service/2026-07-29"
)

// DefaultIngestAPIVersion matches the entitlements-service Contributing Devs Ingest API version.
const DefaultIngestAPIVersion = "2024-10-15"

// IngestRequest is the JSON:API body for one entity ingest POST.
type IngestRequest = v20260729.CreateContributingDevsApplicationVndAPIPlusJSONRequestBody

// IngestClient posts contributor billing ingest payloads to entitlements-service.
type IngestClient struct {
	api     v20260729.ClientWithResponsesInterface
	version string
}

// NewIngestClient creates a client for the ingest endpoint at ingestURL.
// ingestURL must include scheme and host; an optional path prefix is preserved
// (e.g. https://api.snyk.io or https://gateway.example.com/v1).
func NewIngestClient(httpClient *http.Client, ingestURL string) (*IngestClient, error) {
	server, err := ingestServerURL(ingestURL)
	if err != nil {
		return nil, err
	}

	opts := []v20260729.ClientOption{}
	if httpClient != nil {
		opts = append(opts, v20260729.WithHTTPClient(httpClient))
	}

	api, err := v20260729.NewClientWithResponses(server, opts...)
	if err != nil {
		return nil, fmt.Errorf("create entitlements-service client: %w", err)
	}

	return &IngestClient{
		api:     api,
		version: DefaultIngestAPIVersion,
	}, nil
}

// CreateContributingDevs POSTs contributors for one entity to entitlements-service ingest.
func (c *IngestClient) CreateContributingDevs(
	ctx context.Context,
	orgID string,
	authHeader string,
	body IngestRequest,
) (*v20260729.CreateContributingDevsResponse, error) {
	parsedOrgID, err := uuid.Parse(strings.TrimSpace(orgID))
	if err != nil {
		return nil, fmt.Errorf("parse org id: %w", err)
	}

	var editors []v20260729.RequestEditorFn
	if authHeader != "" {
		editors = append(editors, func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", authHeader)
			return nil
		})
	}

	params := &v20260729.CreateContributingDevsParams{
		Version: c.version,
	}

	return c.api.CreateContributingDevsWithApplicationVndAPIPlusJSONBodyWithResponse(
		ctx,
		parsedOrgID,
		params,
		body,
		editors...,
	)
}

func ingestServerURL(ingestURL string) (string, error) {
	parsed, err := url.Parse(ingestURL)
	if err != nil {
		return "", fmt.Errorf("parse ingest URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("ingest URL must include scheme and host")
	}

	parsed.RawQuery = ""
	parsed.Fragment = ""

	return strings.TrimRight(parsed.String(), "/"), nil
}
