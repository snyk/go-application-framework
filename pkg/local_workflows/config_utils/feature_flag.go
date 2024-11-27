package config_utils

import (
	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func AddFeatureFlagToConfig(engine workflow.Engine, configKey string, featureFlagName string) {
	config := engine.GetConfiguration()

	callback := func(existingValue interface{}) (interface{}, error) {
		if existingValue == nil {
			httpClient := engine.GetNetworkAccess().GetHttpClient()
			logger := engine.GetLogger()
			url := config.GetString(configuration.API_URL)
			org := config.GetString(configuration.ORGANIZATION)
			apiClient := api.NewApi(url, httpClient)
			result, err := apiClient.GetFeatureFlag(featureFlagName, org)
			if err != nil {
				logger.Printf("Failed to determine feature flag \"%s\" for org \"%s\": %s", featureFlagName, org, err)
			}
			return result, nil
		} else {
			return existingValue, nil
		}
	}

	config.AddDefaultValue(configKey, callback)
}
