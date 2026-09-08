package config_utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	v20241015 "github.com/snyk/go-application-framework/pkg/apiclients/feature_flag_gateway/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	testutils "github.com/snyk/go-application-framework/pkg/local_workflows/test_utils"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	testOrgID       = "00000000-0000-0000-0000-000000000001"
	testAPIEndpoint = "https://api.snyk.io"
)

func newFlagsResponse(evals []v20241015.FeatureFlagAttributes) *v20241015.ListFeatureFlagsResponse {
	return &v20241015.ListFeatureFlagsResponse{
		ApplicationvndApiJSON200: &struct {
			Data    *v20241015.FeatureFlagsDataItem `json:"data,omitempty"`
			Jsonapi *v20241015.JsonApi              `json:"jsonapi,omitempty"`
		}{
			Data: &v20241015.FeatureFlagsDataItem{
				Attributes: v20241015.FeatureFlagAttributesList{Evaluations: evals},
			},
		},
	}
}

// flagGatewayStub records every batch evaluateFlags was called with and reports
// each requested flag as enabled, except for the ones it was told to omit from
// the response.
type flagGatewayStub struct {
	mu      sync.Mutex
	batches [][]string
	omit    map[string]bool
}

func stubFlagGateway(t *testing.T, omitFromResponse ...string) *flagGatewayStub {
	t.Helper()

	stub := &flagGatewayStub{omit: make(map[string]bool, len(omitFromResponse))}
	for _, flag := range omitFromResponse {
		stub.omit[flag] = true
	}

	originalEvaluateFlags := evaluateFlags
	t.Cleanup(func() { evaluateFlags = originalEvaluateFlags })

	evaluateFlags = func(
		config configuration.Configuration,
		engine workflow.Engine,
		flags []string,
		org uuid.UUID,
	) (*v20241015.ListFeatureFlagsResponse, error) {
		if len(flags) == 0 {
			t.Error("evaluateFlags must never be called without flags")
		}

		stub.mu.Lock()
		stub.batches = append(stub.batches, slices.Clone(flags))
		stub.mu.Unlock()

		enabled := true
		evaluations := make([]v20241015.FeatureFlagAttributes, 0, len(flags))
		for _, flag := range flags {
			if stub.omit[flag] {
				continue
			}
			evaluations = append(evaluations, v20241015.FeatureFlagAttributes{Key: flag, Value: &enabled})
		}

		return newFlagsResponse(evaluations), nil
	}

	return stub
}

func (s *flagGatewayStub) recordedBatches() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.batches)
}

func newFlagTestConfig() configuration.Configuration {
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, testAPIEndpoint)
	config.Set(configuration.ORGANIZATION, testOrgID)
	return config
}

func newFlagTestEngine(t *testing.T, config configuration.Configuration) workflow.Engine {
	t.Helper()

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	logger := zerolog.Logger{}
	mockEngine := mocks.NewMockEngine(ctrl)
	mockEngine.EXPECT().GetConfiguration().Return(config).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(&logger).AnyTimes()

	return mockEngine
}

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
			AddFeatureFlagsToConfig(engine, map[string]string{testConfigKey: flag})
			return nil
		},
		true,
		false,
		"application/vnd.api+json",
	)
}

func Test_AddFeatureFlagGatewayToConfig(t *testing.T) {
	testConfigKey := "test_feature_flag"
	testFeatureFlagName := "testFeatureFlag"

	var requestedOrgs []string
	var requestedAPIs []string

	httpClient := testutils.NewTestClient(func(req *http.Request) *http.Response {
		requestedAPIs = append(requestedAPIs, "https://"+req.Host)

		parts := strings.Split(req.URL.Path, "/")
		org := ""
		for i := 0; i < len(parts)-1; i++ {
			if parts[i] == "orgs" && i+1 < len(parts) {
				org = parts[i+1]
				break
			}
		}
		requestedOrgs = append(requestedOrgs, org)

		enabled := org == testOrgID
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
	config.Set(configuration.API_URL, testAPIEndpoint)
	config.Set(configuration.ORGANIZATION, testOrgID)

	mockEngine.EXPECT().GetConfiguration().Return(config).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(&logger).AnyTimes()
	mockEngine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()
	mockNetworkAccess.EXPECT().GetHttpClient().Return(httpClient).AnyTimes()
	mockNetworkAccess.EXPECT().Clone().Return(mockNetworkAccess).AnyTimes()
	mockNetworkAccess.EXPECT().SetConfiguration(gomock.Any()).AnyTimes()

	AddFeatureFlagsToConfig(mockEngine, map[string]string{testConfigKey: testFeatureFlagName})

	assert.Len(t, requestedOrgs, 0)
	assert.Len(t, requestedAPIs, 0)

	result1 := config.GetBool(testConfigKey)
	assert.True(t, result1)
	assert.Equal(t, []string{testOrgID}, requestedOrgs)
	assert.Equal(t, []string{testAPIEndpoint}, requestedAPIs)
}

func Test_AddFeatureFlagsToConfig_ConcurrentRegistrationAndBatching(t *testing.T) {
	flagCount := 50

	stub := stubFlagGateway(t)
	config := newFlagTestConfig()
	engine := newFlagTestEngine(t, config)

	var wg sync.WaitGroup
	for i := 0; i < flagCount; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			configKey := fmt.Sprintf("concurrent_key_%d", i)
			flagName := fmt.Sprintf("concurrent-flag-%d", i)
			AddFeatureFlagsToConfig(engine, map[string]string{configKey: flagName})
		}(i)
	}
	wg.Wait()

	result := config.GetBool("concurrent_key_0")
	assert.True(t, result)

	for i := 1; i < flagCount; i++ {
		configKey := fmt.Sprintf("concurrent_key_%d", i)
		assert.True(t, config.GetBool(configKey), "flag %s should be resolvable", configKey)
	}

	expectedFlags := make([]string, flagCount)
	for i := 0; i < flagCount; i++ {
		expectedFlags[i] = fmt.Sprintf("concurrent-flag-%d", i)
	}
	slices.Sort(expectedFlags)

	assert.Equal(t, [][]string{expectedFlags}, stub.recordedBatches(),
		"all registered flags must resolve from a single batched API call")
}

func Test_AddFeatureFlagsToConfig_RegistrationsBeforeFirstAccessShareOneRequest(t *testing.T) {
	stub := stubFlagGateway(t)
	config := newFlagTestConfig()
	engine := newFlagTestEngine(t, config)

	AddFeatureFlagsToConfig(engine, map[string]string{"batched_key_a": "batched-flag-a"})
	AddFeatureFlagsToConfig(engine, map[string]string{"batched_key_b": "batched-flag-b"})
	AddFeatureFlagsToConfig(engine, map[string]string{"batched_key_c": "batched-flag-c"})

	assert.True(t, config.GetBool("batched_key_b"))
	assert.True(t, config.GetBool("batched_key_a"))
	assert.True(t, config.GetBool("batched_key_c"))

	assert.Equal(t, [][]string{{"batched-flag-a", "batched-flag-b", "batched-flag-c"}}, stub.recordedBatches(),
		"the first access must look up every flag registered so far")
}

func Test_AddFeatureFlagsToConfig_LateRegistrationIsLookedUp(t *testing.T) {
	stub := stubFlagGateway(t)
	config := newFlagTestConfig()
	engine := newFlagTestEngine(t, config)

	AddFeatureFlagsToConfig(engine, map[string]string{"early_key": "early-flag"})
	assert.True(t, config.GetBool("early_key"))

	// registered after the first lookup already happened
	AddFeatureFlagsToConfig(engine, map[string]string{
		"late_key_a": "late-flag-a",
		"late_key_b": "late-flag-b",
	})

	assert.True(t, config.GetBool("late_key_a"), "a flag registered after an earlier lookup must be looked up")
	assert.True(t, config.GetBool("late_key_b"))

	assert.Equal(t, [][]string{{"early-flag"}, {"late-flag-a", "late-flag-b"}}, stub.recordedBatches(),
		"the second lookup must only request the flags that are not known yet")
}

func Test_AddFeatureFlagsToConfig_ClonedConfigurationSharesLookup(t *testing.T) {
	stub := stubFlagGateway(t)
	config := newFlagTestConfig()
	engine := newFlagTestEngine(t, config)

	AddFeatureFlagsToConfig(engine, map[string]string{"clone_key": "clone-flag"})

	clone := config.Clone()
	assert.True(t, clone.GetBool("clone_key"))
	assert.True(t, config.GetBool("clone_key"))

	assert.Equal(t, [][]string{{"clone-flag"}}, stub.recordedBatches(),
		"a cloned configuration must reuse the lookup of the configuration it was cloned from")
}

func Test_AddFeatureFlagsToConfig_LookupIsScopedToApiEndpoint(t *testing.T) {
	stub := stubFlagGateway(t)
	config := newFlagTestConfig()
	engine := newFlagTestEngine(t, config)

	AddFeatureFlagsToConfig(engine, map[string]string{"endpoint_key": "endpoint-flag"})
	assert.True(t, config.GetBool("endpoint_key"))

	otherEndpoint := config.Clone()
	otherEndpoint.Set(configuration.API_URL, "https://api.eu.snyk.io")
	assert.True(t, otherEndpoint.GetBool("endpoint_key"))

	assert.Equal(t, [][]string{{"endpoint-flag"}, {"endpoint-flag"}}, stub.recordedBatches(),
		"a configuration addressing another endpoint must not reuse the lookup")
}

func Test_AddFeatureFlagsToConfig_FlagMissingFromResponseIsNotRequestedAgain(t *testing.T) {
	stub := stubFlagGateway(t, "unreported-flag")
	config := newFlagTestConfig()
	engine := newFlagTestEngine(t, config)

	AddFeatureFlagsToConfig(engine, map[string]string{"unreported_key": "unreported-flag"})

	for i := 0; i < 3; i++ {
		assert.False(t, config.GetBool("unreported_key"))
	}

	assert.Equal(t, [][]string{{"unreported-flag"}}, stub.recordedBatches(),
		"a flag the gateway does not report must resolve to false without being requested again")
}

func Test_AddFeatureFlagsToConfig_ConcurrentReads(t *testing.T) {
	flagCount := 10

	var apiCallCount int32

	originalEvaluateFlags := evaluateFlags
	t.Cleanup(func() { evaluateFlags = originalEvaluateFlags })

	evaluateFlags = func(
		config configuration.Configuration,
		engine workflow.Engine,
		flags []string,
		org uuid.UUID,
	) (*v20241015.ListFeatureFlagsResponse, error) {
		atomic.AddInt32(&apiCallCount, 1)
		time.Sleep(20 * time.Millisecond)
		trueVal := true
		evals := make([]v20241015.FeatureFlagAttributes, len(flags))
		for i, f := range flags {
			evals[i] = v20241015.FeatureFlagAttributes{Key: f, Value: &trueVal}
		}
		return newFlagsResponse(evals), nil
	}

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	mockEngine := mocks.NewMockEngine(ctrl)
	logger := zerolog.Logger{}
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, testAPIEndpoint)
	config.Set(configuration.ORGANIZATION, testOrgID)

	mockEngine.EXPECT().GetConfiguration().Return(config).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(&logger).AnyTimes()

	for i := 0; i < flagCount; i++ {
		configKey := fmt.Sprintf("concurrent_read_key_%d", i)
		flagName := fmt.Sprintf("concurrent-read-flag-%d", i)
		AddFeatureFlagsToConfig(mockEngine, map[string]string{configKey: flagName})
	}

	var wg sync.WaitGroup
	results := make([]bool, flagCount)
	for i := 0; i < flagCount; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			configKey := fmt.Sprintf("concurrent_read_key_%d", i)
			results[i] = config.GetBool(configKey)
		}(i)
	}
	wg.Wait()

	for i, r := range results {
		assert.True(t, r, "flag concurrent_read_key_%d should be true", i)
	}

	assert.Equal(t, int32(1), atomic.LoadInt32(&apiCallCount),
		"concurrent reads for the same org should coalesce into a single API call")
}

func TestAreFeaturesEnabled_PartialAndNilValue(t *testing.T) {
	orgID := uuid.NewString()

	originalEvaluateFlags := evaluateFlags
	t.Cleanup(func() { evaluateFlags = originalEvaluateFlags })

	tests := []struct {
		name        string
		requested   []string
		evaluations []v20241015.FeatureFlagAttributes
		want        map[string]bool
	}{
		{
			name:      "missing flag defaults to false",
			requested: []string{"flag-true", "flag-missing"},
			evaluations: func() []v20241015.FeatureFlagAttributes {
				v := true
				return []v20241015.FeatureFlagAttributes{
					{Key: "flag-true", Value: &v},
				}
			}(),
			want: map[string]bool{
				"flag-true":    true,
				"flag-missing": false,
			},
		},
		{
			name:      "value == nil defaults to false",
			requested: []string{"flag-nil"},
			evaluations: []v20241015.FeatureFlagAttributes{
				{Key: "flag-nil", Value: nil},
			},
			want: map[string]bool{
				"flag-nil": false,
			},
		},
		{
			name:      "unknown evaluation key is ignored (requested still defaulted)",
			requested: []string{"flag-a"},
			evaluations: func() []v20241015.FeatureFlagAttributes {
				v := true
				return []v20241015.FeatureFlagAttributes{
					{Key: "some-other-flag", Value: &v},
				}
			}(),
			want: map[string]bool{
				"flag-a": false,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			evaluateFlags = func(
				config configuration.Configuration,
				engine workflow.Engine,
				flags []string,
				orgID uuid.UUID,
			) (*v20241015.ListFeatureFlagsResponse, error) {
				return newFlagsResponse(tc.evaluations), nil
			}

			got, err := areFeaturesEnabled(nil, nil, orgID, tc.requested...)
			assert.NoError(t, err)

			for _, key := range tc.requested {
				wantVal, ok := tc.want[key]
				if !ok {
					t.Fatalf("test case missing expected value for requested flag %q", key)
				}
				assert.Equal(t, wantVal, got[key], "flag %q", key)
			}
		})
	}
}

func TestIsFeatureEnabled_Error_InvalidUUID(t *testing.T) {
	enabled, err := areFeaturesEnabled(nil, nil, "not-a-uuid", "my-flag")

	assert.True(t, uuid.IsInvalidLengthError(err))
	assert.False(t, enabled["my-flag"])
}

func TestIsFeatureEnabled_Error_EvaluateFlagsReturnsError(t *testing.T) {
	flag := "my-flag"
	orgID := uuid.NewString()
	expectedErr := errors.New("gateway blew up")

	originalEvaluateFlags := evaluateFlags
	t.Cleanup(func() { evaluateFlags = originalEvaluateFlags })

	evaluateFlags = func(
		config configuration.Configuration, engine workflow.Engine, flags []string, orgID uuid.UUID,
	) (featureFlagsResponse *v20241015.ListFeatureFlagsResponse, retErr error) {
		return nil, expectedErr
	}

	enabled, err := areFeaturesEnabled(nil, nil, orgID, flag)
	assert.ErrorIs(t, err, expectedErr)
	assert.False(t, enabled[flag])
}

func TestIsFeatureEnabled_Error_InvalidEvaluateFlagsResponse(t *testing.T) {
	flag := "my-flag"
	orgID := uuid.NewString()

	originalEvaluateFlags := evaluateFlags
	t.Cleanup(func() { evaluateFlags = originalEvaluateFlags })

	evaluateFlags = func(
		config configuration.Configuration,
		engine workflow.Engine,
		flags []string,
		orgID uuid.UUID,
	) (*v20241015.ListFeatureFlagsResponse, error) {
		return &v20241015.ListFeatureFlagsResponse{}, nil
	}

	enabled, err := areFeaturesEnabled(nil, nil, orgID, flag)

	assert.ErrorIs(t, err, errInvalidEvaluateFlagsResponse)
	assert.False(t, enabled[flag])
}
