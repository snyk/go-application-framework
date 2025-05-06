package config_utils

import (
	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"sync"
)

//go:generate $GOPATH/bin/mockgen -source=feature_flag.go -destination ../../mocks/feature_flag.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/local_workflows/config_utils

func AddFeatureFlagToConfig(engine workflow.Engine, configKey string, featureFlagName string) {
	config := engine.GetConfiguration()

	callback := func(existingValue interface{}) (interface{}, error) {
		if existingValue == nil {
			return CurrentFeatureFlagChecker().GetFeatureFlag(engine, featureFlagName)
		} else {
			return existingValue, nil
		}
	}

	config.AddDefaultValue(configKey, callback)
}

type FeatureFlagChecker interface {
	GetFeatureFlag(engine workflow.Engine, featureFlagName string) (bool, error)
}

type featureFlagCheckerImpl struct {
}

var (
	currentFFC FeatureFlagChecker
	mutex      = &sync.RWMutex{}
)

func CurrentFeatureFlagChecker() FeatureFlagChecker {
	mutex.RLock()
	defer mutex.RUnlock()
	if currentFFC == nil {
		currentFFC = &featureFlagCheckerImpl{}
	}
	return currentFFC
}

func SetCurrentFeatureFlagChecker(ffc FeatureFlagChecker) {
	mutex.Lock()
	defer mutex.Unlock()
	currentFFC = ffc
}

func (ffc *featureFlagCheckerImpl) GetFeatureFlag(engine workflow.Engine, featureFlagName string) (bool, error) {
	config := engine.GetConfiguration()
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
}
