package featureflaggateway

import (
	"context"
	"fmt"

	"net/url"

	"github.com/google/uuid"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/feature_flag_gateway/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	defaultVersion = "2024-10-15"
)

var newClient = newClientImpl

func newClientImpl(engine workflow.Engine, config configuration.Configuration) (v20241015.ClientWithResponsesInterface, error) {
	client := engine.GetNetworkAccess().GetHttpClient()
	baseUrl, err := url.JoinPath(config.GetString(configuration.API_URL), "hidden")
	if err != nil {
		return nil, err
	}
	return v20241015.NewClientWithResponses(baseUrl, v20241015.WithHTTPClient(client))
}

// EvaluateFlags evaluates feature flags for a given organization.
func EvaluateFlags(config configuration.Configuration, engine workflow.Engine, flags []string, orgID uuid.UUID) (featureFlagsResponse *v20241015.ListFeatureFlagsResponse, retErr error) {
	ffgClient, err := newClient(engine, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create feature flag gateway client")
	}

	reqBody := buildRequest(flags)
	featureFlagsResponse, err = ffgClient.
		ListFeatureFlagsWithApplicationVndAPIPlusJSONBodyWithResponse(
			context.Background(),
			orgID,
			&v20241015.ListFeatureFlagsParams{Version: defaultVersion},
			reqBody,
		)
	if err != nil {
		return nil, fmt.Errorf("create evaluate flags request: %w", err)
	}

	return featureFlagsResponse, nil
}

func buildRequest(flags []string) v20241015.FeatureFlagRequest {
	return v20241015.FeatureFlagRequest{
		Data: v20241015.FeatureFlagsData{
			Type: "feature_flags_evaluation",
			Attributes: v20241015.FeatureFlagsRequestAttributes{
				Flags: flags,
			},
		},
	}
}
