package config_utils

import (
	"fmt"

	"github.com/google/uuid"
	featureflaggateway "github.com/snyk/go-application-framework/pkg/apiclients/feature_flag_gateway"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/feature_flag_gateway/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

var evaluateFlags = featureflaggateway.EvaluateFlags

func AddFeatureFlagGatewayToConfig(engine workflow.Engine, configKey string, featureFlagName string) {
	config := engine.GetConfiguration()
	err := config.AddKeyDependency(configKey, configuration.ORGANIZATION)
	if err != nil {
		engine.GetLogger().Err(err).Msgf("Failed to add dependency for %s", configKey)
	}

	callback := func(c configuration.Configuration, existingValue any) (any, error) {
		if existingValue != nil {
			return existingValue, nil
		}
		enabled, enabledErr := isFeatureEnabled(
			c,
			engine,
			config.GetString(configuration.ORGANIZATION),
			featureFlagName,
		)
		if enabledErr != nil {
			return enabled, fmt.Errorf("check feature flag: %w", err)
		}
		return enabled, nil
	}

	config.AddDefaultValue(configKey, callback)
}

func isFeatureEnabled(
	config configuration.Configuration,
	engine workflow.Engine,
	orgID string,
	flag string,
) (bool, error) {
	orgUUID, err := uuid.Parse(orgID)
	if err != nil {
		return false, err
	}

	resp, err := evaluateFlags(config, engine, []string{flag}, orgUUID)
	if err != nil || !validEvaluateFlagsResponse(resp) {
		return false, err
	}

	evaluations := resp.ApplicationvndApiJSON200.Data.Attributes.Evaluations
	for _, e := range evaluations {
		if e.Key == flag {
			return *e.Value, nil
		}
	}
	return false, nil
}

func validEvaluateFlagsResponse(resp *v20241015.ListFeatureFlagsResponse) bool {
	return resp != nil &&
		resp.ApplicationvndApiJSON200 != nil &&
		resp.ApplicationvndApiJSON200.Data != nil
}
