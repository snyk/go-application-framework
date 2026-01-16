package config_utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/feature_flag_gateway/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	testutils "github.com/snyk/go-application-framework/pkg/local_workflows/test_utils"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AddFeatureFlagGatewayToConfig_CacheDependentOnOrg(t *testing.T) {
	testConfigKey := "test_feature_flag"
	flag := "my-flag"

	testutils.CheckCacheRespectOrgDependency(
		t,
		testConfigKey,
		func(isFirstCall bool) any {
			return struct {
				Data    *v20241015.FeatureFlagsDataItem `json:"data,omitempty"`
				Jsonapi *v20241015.JsonApi              `json:"jsonapi,omitempty"`
			}{
				Data: &v20241015.FeatureFlagsDataItem{
					Attributes: v20241015.FeatureFlagAttributesList{
						Evaluations: []v20241015.FeatureFlagAttributes{
							{
								Key:   flag,
								Value: &isFirstCall,
							},
						},
					},
				},
				Jsonapi: &v20241015.JsonApi{
					Version: "1.0",
				},
			}
		},
		func(engine workflow.Engine) error {
			AddFeatureFlagGatewayToConfig(engine, testConfigKey, flag)
			return nil
		},
		true,
		false,
		"application/vnd.api+json",
	)
}

func Test_AddFeatureFlagGatewayToConfig(t *testing.T) {
	globalOrg := "00000000-0000-0000-0000-000000000001"
	globalAPIEndpoint := "https://api.snyk.io"

	testConfigKey := "test_feature_flag"
	testFeatureFlagName := "testFeatureFlag"

	var requestedOrgs []string
	var requestedAPIs []string

	httpClient := testutils.NewTestClient(func(req *http.Request) *http.Response {
		requestedAPIs = append(requestedAPIs, "https://"+req.Host)

		// Extract org from path: /hidden/orgs/<org>/feature_flags/evaluation
		parts := strings.Split(req.URL.Path, "/")
		org := ""
		for i := 0; i < len(parts)-1; i++ {
			if parts[i] == "orgs" && i+1 < len(parts) {
				org = parts[i+1]
				break
			}
		}
		requestedOrgs = append(requestedOrgs, org)

		enabled := org == globalOrg
		response := struct {
			Data    *v20241015.FeatureFlagsDataItem `json:"data,omitempty"`
			Jsonapi *v20241015.JsonApi              `json:"jsonapi,omitempty"`
		}{
			Data: &v20241015.FeatureFlagsDataItem{
				Attributes: v20241015.FeatureFlagAttributesList{
					Evaluations: []v20241015.FeatureFlagAttributes{
						{
							Key:   testFeatureFlagName,
							Value: &enabled,
						},
					},
				},
			},
		}

		responseJSON, err := json.Marshal(response)
		require.NoError(t, err)

		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"application/vnd.api+json"}},
			Body:       io.NopCloser(bytes.NewBuffer(responseJSON)),
		}
	})

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockEngine := mocks.NewMockEngine(ctrl)
	mockNetworkAccess := mocks.NewMockNetworkAccess(ctrl)
	logger := zerolog.Logger{}

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, globalAPIEndpoint)
	config.Set(configuration.ORGANIZATION, globalOrg)

	mockEngine.EXPECT().GetConfiguration().Return(config).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(&logger).AnyTimes()
	mockEngine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()
	mockNetworkAccess.EXPECT().GetHttpClient().Return(httpClient).AnyTimes()
	mockNetworkAccess.EXPECT().Clone().Return(mockNetworkAccess).AnyTimes()
	mockNetworkAccess.EXPECT().SetConfiguration(gomock.Any()).AnyTimes()

	AddFeatureFlagGatewayToConfig(mockEngine, testConfigKey, testFeatureFlagName)

	assert.Len(t, requestedOrgs, 0)
	assert.Len(t, requestedAPIs, 0)

	// Fetch from global config
	result1 := config.GetBool(testConfigKey)
	assert.True(t, result1)
	assert.Equal(t, []string{globalOrg}, requestedOrgs)
	assert.Equal(t, []string{globalAPIEndpoint}, requestedAPIs)
}

func TestIsFeatureEnabled_Success(t *testing.T) {
	flag := "my-flag"
	orgID := uuid.NewString()
	value := true

	evaluateFlags = func(
		config configuration.Configuration,
		engine workflow.Engine,
		flags []string,
		orgID uuid.UUID,
	) (*v20241015.ListFeatureFlagsResponse, error) {
		return &v20241015.ListFeatureFlagsResponse{
			ApplicationvndApiJSON200: &struct {
				Data    *v20241015.FeatureFlagsDataItem `json:"data,omitempty"`
				Jsonapi *v20241015.JsonApi              `json:"jsonapi,omitempty"`
			}{
				Data: &v20241015.FeatureFlagsDataItem{
					Attributes: v20241015.FeatureFlagAttributesList{
						Evaluations: []v20241015.FeatureFlagAttributes{
							{
								Key:   flag,
								Value: &value,
							},
						},
					},
				},
			},
		}, nil
	}

	enabled, err := isFeatureEnabled(nil, nil, orgID, flag)
	assert.NoError(t, err)
	assert.True(t, enabled)
}

func TestIsFeatureEnabled_Error_InvalidUUID(t *testing.T) {
	enabled, err := isFeatureEnabled(nil, nil, "not-a-uuid", "my-flag")

	assert.True(t, uuid.IsInvalidLengthError(err))
	assert.False(t, enabled)
}

func TestIsFeatureEnabled_Error_EvaluateFlagsReturnsError(t *testing.T) {
	flag := "my-flag"
	orgID := uuid.NewString()
	expectedErr := errors.New("gateway blew up")
	evaluateFlags = func(
		config configuration.Configuration, engine workflow.Engine, flags []string, orgID uuid.UUID,
	) (featureFlagsResponse *v20241015.ListFeatureFlagsResponse, retErr error) {
		return nil, expectedErr
	}

	enabled, err := isFeatureEnabled(nil, nil, orgID, flag)
	assert.ErrorIs(t, err, expectedErr)
	assert.False(t, enabled)
}
