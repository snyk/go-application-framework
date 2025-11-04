package testutils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// roundTripFn
type roundTripFn func(req *http.Request) *http.Response
type roundTripErrorFn func(req *http.Request) *http.Response

func (f roundTripFn) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func (f roundTripErrorFn) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("yay, a test error")
}

// NewTestClient return *http.Client with Transport replaced to avoid making real calls
func NewTestClient(fn roundTripFn) *http.Client {
	return &http.Client{
		Transport: fn,
	}
}

func NewErrorProducingTestClient(fn roundTripErrorFn) *http.Client {
	return &http.Client{
		Transport: fn,
	}
}

// CheckConfigCachesDependency tests that a config value properly invalidates its cache when a dependency changes.
// This is for testing config-to-config dependencies (e.g., ConfigurationSastEnabled depends on ConfigurationSastSettings).
func CheckConfigCachesDependency(
	t *testing.T,
	configKey string,
	dependencyKey string,
	defaultValueFuncFactory func(engine workflow.Engine) configuration.DefaultValueFunction,
	dependencyValueBefore any,
	dependencyValueAfter any,
	expectedValueBefore any,
	expectedValueAfter any,
) {
	t.Helper()

	require.NotEqual(t, expectedValueBefore, expectedValueAfter, "expected values before and after key dependency change should be different")

	// Setup config with caching enabled
	config := configuration.NewWithOpts(configuration.WithCachingEnabled(10 * time.Minute))

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	logger := zerolog.Logger{}

	mockEngine.EXPECT().GetConfiguration().Return(config).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(&logger).AnyTimes()

	// Create the default value function (which also registers the dependency)
	defaultValueFunc := defaultValueFuncFactory(mockEngine)
	// Register the default value function, if it is not already registered
	// (the factory returns nil if it is already registered)
	if defaultValueFunc != nil {
		wrappedDefaultValueFunc := func(config configuration.Configuration, existingValue any) (any, error) {
			t.Logf("defaultValueFunc called")
			return defaultValueFunc(config, existingValue)
		}
		config.AddDefaultValue(configKey, wrappedDefaultValueFunc)
	}

	// Set initial dependency value
	config.Set(dependencyKey, dependencyValueBefore)

	// First call - should compute from dependency
	result1, err := config.GetWithError(configKey)
	require.NoError(t, err)
	assert.Equal(t, expectedValueBefore, result1, "First call should return value based on initial dependency")

	// Second call with same dependency - should use cache
	result2, err := config.GetWithError(configKey)
	require.NoError(t, err)
	assert.Equal(t, expectedValueBefore, result2, "Second call should return cached value")

	// Change the dependency value
	config.Set(dependencyKey, dependencyValueAfter)

	// Third call - cache should be invalidated, should compute from new dependency
	result3, err := config.GetWithError(configKey)
	require.NoError(t, err)
	assert.Equal(t, expectedValueAfter, result3, "Third call should return value based on new dependency (cache invalidated)")
}

// CheckCacheRespectOrgDependency tests ORGANIZATION-based cache invalidation with HTTP API call mocking.
// Verifies cache is cleared when ORGANIZATION changes and API is called again with new org.
func CheckCacheRespectOrgDependency(
	t *testing.T,
	configKey string,
	httpResponseFn func(isFirstCall bool) any,
	initFunc func(engine workflow.Engine) error,
	expectedValueBeforeOrgChange any,
	expectedValueAfterOrgChange any,
) {
	t.Helper()

	require.NotEqual(t, expectedValueBeforeOrgChange, expectedValueAfterOrgChange, "expected response before and after org change should be different")

	// Setup config with caching enabled
	config := configuration.NewWithOpts(configuration.WithCachingEnabled(10 * time.Minute))
	config.Set(configuration.ORGANIZATION, "org-1")
	config.Set(configuration.API_URL, "https://api.snyk.io")

	// Mock the API and track the call count
	apiCallCount := 0
	httpClient := NewTestClient(func(req *http.Request) *http.Response {
		apiCallCount++
		t.Logf("Faking API call #%d for URL: %s", apiCallCount, req.URL.Path)
		if apiCallCount > 2 {
			require.FailNow(t, "API should not be called more than twice")
		}

		response := httpResponseFn(apiCallCount == 1)
		responseJSON, err := json.Marshal(response)
		require.NoError(t, err)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBuffer(responseJSON)),
		}
	})

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockNetworkAccess := mocks.NewMockNetworkAccess(ctrl)
	logger := zerolog.Logger{}

	mockEngine.EXPECT().GetConfiguration().Return(config).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(&logger).AnyTimes()
	// Pretend to support workflow registration (init functions may register workflows, but we don't use them)
	mockEngine.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	mockEngine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()
	mockNetworkAccess.EXPECT().Clone().Return(mockNetworkAccess).AnyTimes() // Don't actually clone, we don't need to for this test.
	mockNetworkAccess.EXPECT().SetConfiguration(gomock.Any()).AnyTimes()    // Don't actually override the configuration, we don't need to for this test.
	mockNetworkAccess.EXPECT().GetHttpClient().Return(httpClient).AnyTimes()

	// Call the init function (which registers config defaults)
	err := initFunc(mockEngine)
	require.NoError(t, err, "initFunc should not return an error")

	// First call - should invoke API
	result1, err := config.GetWithError(configKey)
	require.NoError(t, err)
	assert.Equal(t, expectedValueBeforeOrgChange, result1, "First call should return expectedFetch1And2")
	assert.Equal(t, 1, apiCallCount, "API should be called on first read")

	// Second call with same org - should use cache
	result2, err := config.GetWithError(configKey)
	require.NoError(t, err)
	assert.Equal(t, expectedValueBeforeOrgChange, result2, "Second call should return expectedFetch1And2 again (cached)")
	assert.Equal(t, 1, apiCallCount, "API should not be called on second read (cached)")

	// Change the organization - this should clear the cache
	config.Set(configuration.ORGANIZATION, "org-2")

	// Third call - cache should be invalidated, API called again
	result3, err := config.GetWithError(configKey)
	require.NoError(t, err)
	assert.Equal(t, expectedValueAfterOrgChange, result3, "Third call should return expectedFetch3 (cache was cleared, so fetched again)")
	assert.Equal(t, 2, apiCallCount, "API should be called again after org change")
}
