package config_utils

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/api/contract"
	"github.com/snyk/go-application-framework/pkg/configuration"
	testutils "github.com/snyk/go-application-framework/pkg/local_workflows/test_utils"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_AddFeatureFlagToConfig_CacheDependentOnOrg(t *testing.T) {
	testConfigKey := "test_feature_flag"
	testutils.CheckCacheRespectOrgDependency(
		t,
		testConfigKey,
		func(isFirstCall bool) any {
			return map[string]bool{
				"ok": isFirstCall,
			}
		},
		func(engine workflow.Engine) error {
			AddFeatureFlagToConfig(engine, testConfigKey, "testFeatureFlag")
			return nil
		},
		true,
		false,
	)
}

func Test_AddFeatureFlagToConfig_UsesClonedConfigOrgAPIURLAndNetworkAccess(t *testing.T) {
	globalOrg := "00000000-0000-0000-0000-000000000001"
	clonedOrg := "00000000-0000-0000-0000-000000000002"
	globalAPIEndpoint := "https://api.snyk.io"
	cloneAPIEndpoint := "https://api.eu.snyk.io"
	testConfigKey := "test_feature_flag"
	testFeatureFlagName := "testFeatureFlag"

	// Track which org IDs and API URLs were requested
	var requestedOrgs []string
	var requestedAPIs []string

	httpClient := testutils.NewTestClient(func(req *http.Request) *http.Response {
		// Extract org from query param and API URL from request
		org := req.URL.Query().Get("org")
		apiUrl := "https://" + req.Host
		requestedOrgs = append(requestedOrgs, org)
		requestedAPIs = append(requestedAPIs, apiUrl)

		// Mock different response per org
		response := contract.OrgFeatureFlagResponse{
			Code: http.StatusOK,
			Ok:   org == globalOrg,
		}
		responseJSON, err := json.Marshal(response)
		require.NoError(t, err)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBuffer(responseJSON)),
		}
	})

	ctrl := gomock.NewController(t)
	mockEngine := mocks.NewMockEngine(ctrl)
	mockNetworkAccess := mocks.NewMockNetworkAccess(ctrl)
	logger := zerolog.Logger{}

	config := configuration.NewInMemory()
	config.Set(configuration.API_URL, globalAPIEndpoint)
	config.Set(configuration.ORGANIZATION, globalOrg)

	mockEngine.EXPECT().GetConfiguration().Return(config).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(&logger).AnyTimes()
	mockEngine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()
	mockNetworkAccess.EXPECT().GetHttpClient().Return(httpClient).AnyTimes()
	mockNetworkAccess.EXPECT().Clone().Return(mockNetworkAccess).AnyTimes()
	mockNetworkAccess.EXPECT().SetConfiguration(gomock.Any()).AnyTimes()

	AddFeatureFlagToConfig(mockEngine, testConfigKey, testFeatureFlagName)
	assert.Len(t, requestedOrgs, 0, "Not expecting any requests before the first fetch")
	assert.Len(t, requestedAPIs, 0, "Not expecting any requests before the first fetch")

	// Fetch feature flag from global config
	result1 := config.GetBool(testConfigKey)
	assert.True(t, result1, "Expecting globalOrg to have the feature flag enabled, since that is what we mocked it to be")
	assert.Equal(t, []string{globalOrg}, requestedOrgs, "First fetch should use globalOrg")
	assert.Equal(t, []string{globalAPIEndpoint}, requestedAPIs, "First fetch should use globalAPIEndpoint")

	// Clone config and change both org and API URL
	clonedConfig := config.Clone()
	clonedConfig.Set(configuration.ORGANIZATION, clonedOrg)
	clonedConfig.Set(configuration.API_URL, cloneAPIEndpoint)
	assert.Len(t, requestedOrgs, 1, "Cloning and setting values should not make requests")
	assert.Len(t, requestedAPIs, 1, "Cloning and setting values should not make requests")

	// Fetch feature flag from cloned config
	result2 := clonedConfig.GetBool(testConfigKey)
	assert.False(t, result2, "Expecting clonedOrg to have the feature flag disabled, since that is what we mocked it to be")
	assert.Equal(t, []string{globalOrg, clonedOrg}, requestedOrgs, "Second fetch should use clonedOrg")
	assert.Equal(t, []string{globalAPIEndpoint, cloneAPIEndpoint}, requestedAPIs, "Second fetch should use cloneAPIEndpoint")
}
