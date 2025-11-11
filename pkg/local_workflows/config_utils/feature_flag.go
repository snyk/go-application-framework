package config_utils

import (
	"net/http"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func AddFeatureFlagToConfig(engine workflow.Engine, configKey string, featureFlagName string) {
	config := engine.GetConfiguration()
	err := config.AddKeyDependency(configKey, configuration.ORGANIZATION)
	if err != nil {
		engine.GetLogger().Err(err).Msgf("Failed to add dependency for %s", configKey)
	}

	callback := func(c configuration.Configuration, existingValue any) (any, error) {
		if existingValue != nil {
			return existingValue, nil
		}

		localNetworkStack := engine.GetNetworkAccess().Clone()
		localNetworkStack.SetConfiguration(c)
		httpClient := localNetworkStack.GetHttpClient()
		return GetFeatureFlagValue(featureFlagName, c, httpClient)
	}

	config.AddDefaultValue(configKey, callback)
}

func GetFeatureFlagValue(featureFlagName string, config configuration.Configuration, httpClient *http.Client) (bool, error) {
	url := config.GetString(configuration.API_URL)
	org := config.GetString(configuration.ORGANIZATION)
	apiClient := api.NewApi(url, httpClient)
	result, err := apiClient.GetFeatureFlag(featureFlagName, org)
	return result, err
}
