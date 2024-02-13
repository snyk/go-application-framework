package reportanalytics

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/pkg/errors"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func getReportAnalyticsEndpoint(config configuration.Configuration) string {
	url := fmt.Sprintf(
		"%s/hidden/orgs/%s/analytics?version=2023-11-09~experimental",
		config.GetString(configuration.API_URL),
		config.Get(configuration.ORGANIZATION),
	)
	return url
}

func callEndpoint(invocationCtx workflow.InvocationContext, payload []byte, jsonContentType string) error {
	logger := invocationCtx.GetLogger()
	url := getReportAnalyticsEndpoint(invocationCtx.GetConfiguration())

	ctx := context.Background()

	// Create a request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(payload))
	if err != nil {
		logger.Printf("error creating request: %v\n", err)
		return errors.Wrap(err, "failed to create request")
	}
	req.Header.Set("Content-Type", jsonContentType)

	// Send the request

	resp, err := invocationCtx.GetNetworkAccess().GetHttpClient().Do(req)
	if err != nil {
		logger.Printf("error sending request: %v\n", err)
		return errors.Wrap(err, "failed to send request")
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("error sending request %v", resp.Status)
	}

	defer func(Body io.ReadCloser) { _ = Body.Close() }(resp.Body)
	return nil
}
