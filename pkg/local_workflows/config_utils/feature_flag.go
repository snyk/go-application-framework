package config_utils

import (
	"net/http"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func AddFeatureFlagToConfig(engine workflow.Engine, configKey string, featureFlagName string) {
	config := engine.GetConfiguration()

	callback := func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		if existingValue == nil {
			httpClient := engine.GetNetworkAccess().GetHttpClient()
			return GetFeatureFlagValue(featureFlagName, config, httpClient)
		} else {
			return existingValue, nil
		}
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
