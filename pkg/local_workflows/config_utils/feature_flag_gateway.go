package config_utils

import (
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
		enabled := isFeatureEnabled(
			c,
			engine,
			config.GetString(configuration.ORGANIZATION),
			featureFlagName,
		)
		return enabled, nil
	}

	config.AddDefaultValue(configKey, callback)
}

func isFeatureEnabled(
	config configuration.Configuration,
	engine workflow.Engine,
	orgID string,
	flag string,
) bool {
	orgUUID, err := uuid.Parse(orgID)
	if err != nil {
		return false
	}

	resp, err := evaluateFlags(config, engine, []string{flag}, orgUUID)
	if err != nil || !validEvaluateFlagsResponse(resp) {
		return false
	}

	evaluations := resp.ApplicationvndApiJSON200.Data.Attributes.Evaluations
	for _, e := range evaluations {
		if e.Key == flag {
			return *e.Value
		}
	}
	return false
}

func validEvaluateFlagsResponse(resp *v20241015.ListFeatureFlagsResponse) bool {
	return resp != nil &&
		resp.ApplicationvndApiJSON200 != nil &&
		resp.ApplicationvndApiJSON200.Data != nil
}
