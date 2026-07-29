package entitlements_service

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	v20260729 "github.com/snyk/go-application-framework/pkg/apiclients/entitlements_service/2026-07-29"
)

// IngestPath is the draft entitlements-service contributor ingest path.
// TODO: replace spec.yaml with the official entitlements-service OpenAPI once available.
const IngestPath = "/rest/api/hidden/contributors/ingest"

// IngestRequest is the contributor billing ingest payload.
type IngestRequest = v20260729.ContributorIngestRequest

// IngestClient posts contributor billing ingest payloads to entitlements-service.
type IngestClient struct {
	api v20260729.ClientWithResponsesInterface
}

// NewIngestClient creates a client for the ingest endpoint at ingestURL.
// ingestURL may be a host root (e.g. https://api.snyk.io) or include IngestPath.
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

	return &IngestClient{api: api}, nil
}

// IngestContributors POSTs a contributor billing ingest payload.
func (c *IngestClient) IngestContributors(
	ctx context.Context,
	authHeader string,
	body IngestRequest,
) (*v20260729.IngestContributorsResponse, error) {
	var editors []v20260729.RequestEditorFn
	if authHeader != "" {
		editors = append(editors, func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", authHeader)
			return nil
		})
	}

	return c.api.IngestContributorsWithResponse(ctx, body, editors...)
}

func ingestServerURL(ingestURL string) (string, error) {
	parsed, err := url.Parse(ingestURL)
	if err != nil {
		return "", fmt.Errorf("parse ingest URL: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("ingest URL must include scheme and host")
	}

	parsed.Path = strings.TrimSuffix(parsed.Path, IngestPath)
	parsed.RawPath = ""
	parsed.RawQuery = ""
	parsed.Fragment = ""

	return strings.TrimRight(parsed.String(), "/"), nil
}
