package localworkflows

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
)

func Test_auth_oauth(t *testing.T) {
	mockCtl := gomock.NewController(t)
	logContent := &bytes.Buffer{}
	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	logger := zerolog.New(logContent)
	engine := mocks.NewMockEngine(mockCtl)
	authenticator := mocks.NewMockAuthenticator(mockCtl)
	analytics := analytics.New()
	config.Set(configuration.PREVIEW_FEATURES_ENABLED, true)
	engine.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	engine.EXPECT().Init().Times(1)

	err := InitAuth(engine)
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	mockDeriveEndpoint := func(pat string, config configuration.Configuration, client *http.Client, regions []string) (string, error) {
		return "", nil
	}

	t.Run("happy", func(t *testing.T) {
		config.Set(authTypeParameter, nil)
		authenticator.EXPECT().Authenticate().Times(2).Return(nil)
		mockInvocationContext := mocks.NewMockInvocationContext(mockCtl)
		mockInvocationContext.EXPECT().GetConfiguration().Return(config).AnyTimes()
		mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		mockInvocationContext.EXPECT().GetAnalytics().Return(analytics).AnyTimes()
		err = entryPointDI(mockInvocationContext, &logger, engine, authenticator, mockDeriveEndpoint)
		err = entryPointDI(mockInvocationContext, &logger, engine, authenticator, mockDeriveEndpoint)
		assert.NoError(t, err)
	})

	t.Run("unhappy", func(t *testing.T) {
		config.Set(authTypeParameter, nil)
		expectedErr := fmt.Errorf("someting went wrong")
		authenticator.EXPECT().Authenticate().Times(1).Return(expectedErr)
		mockInvocationContext := mocks.NewMockInvocationContext(mockCtl)
		mockInvocationContext.EXPECT().GetConfiguration().Return(config).AnyTimes()
		mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		mockInvocationContext.EXPECT().GetAnalytics().Return(analytics).AnyTimes()
		err = entryPointDI(mockInvocationContext, &logger, engine, authenticator, mockDeriveEndpoint)
		assert.Equal(t, expectedErr, err)
	})
}

func Test_auth_token(t *testing.T) {
	mockCtl := gomock.NewController(t)
	logContent := &bytes.Buffer{}
	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	analytics := analytics.New()
	logger := zerolog.New(logContent)
	engine := mocks.NewMockEngine(mockCtl)
	authenticator := mocks.NewMockAuthenticator(mockCtl)
	mockDeriveEndpoint := func(pat string, config configuration.Configuration, client *http.Client, regions []string) (string, error) {
		return "", nil
	}

	engine.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	engine.EXPECT().Init().Times(1)

	err := InitAuth(engine)
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	t.Run("happy", func(t *testing.T) {
		config.Set(authTypeParameter, auth.AUTH_TYPE_TOKEN)
		engine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any())
		mockInvocationContext := mocks.NewMockInvocationContext(mockCtl)
		mockInvocationContext.EXPECT().GetConfiguration().Return(config).AnyTimes()
		mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		mockInvocationContext.EXPECT().GetAnalytics().Return(analytics).AnyTimes()

		err = entryPointDI(mockInvocationContext, &logger, engine, authenticator, mockDeriveEndpoint)
		assert.NoError(t, err)
	})

	t.Run("automatically switch to token when API token is given", func(t *testing.T) {
		config.Set(authTypeParameter, nil)
		config.Set(ConfigurationNewAuthenticationToken, "00000000-0000-0000-0000-000000000000")
		engine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any())
		mockInvocationContext := mocks.NewMockInvocationContext(mockCtl)
		mockInvocationContext.EXPECT().GetConfiguration().Return(config).AnyTimes()
		mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		mockInvocationContext.EXPECT().GetAnalytics().Return(analytics).AnyTimes()

		err = entryPointDI(mockInvocationContext, &logger, engine, authenticator, mockDeriveEndpoint)
		assert.NoError(t, err)
	})
}

func Test_pat(t *testing.T) {
	const (
		testPAT               = "snyk_pat.12345678.abcdefghijklmnopqrstuvwxyz123456"
		mockedPatEndpoint     = "https://api.snyk.io"
		expectedAPIKeyStorage = auth.CONFIG_KEY_TOKEN
	)

	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	logContent := &bytes.Buffer{}
	logger := zerolog.New(logContent)
	analytics := analytics.New()

	engine := mocks.NewMockEngine(mockCtl)
	authenticator := mocks.NewMockAuthenticator(mockCtl)
	mockNetworkAccess := mocks.NewMockNetworkAccess(mockCtl)
	mockHTTPClient := &http.Client{}

	t.Run("happy", func(t *testing.T) {
		config := configuration.New()
		config.Set(authTypeParameter, auth.AUTH_TYPE_PAT)
		config.Set(ConfigurationNewAuthenticationToken, testPAT)
		config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, "some-oauth-token")
		config.Set(configuration.AUTHENTICATION_TOKEN, "some-legacy-api-token")

		config.Set(configuration.SNYK_REGION_URLS, []string{"https://api.snyk.io"})

		mockInvocationContext := mocks.NewMockInvocationContext(mockCtl)
		mockInvocationContext.EXPECT().GetConfiguration().Return(config).AnyTimes()
		mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		mockInvocationContext.EXPECT().GetAnalytics().Return(analytics).Times(1)
		mockInvocationContext.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).Times(1)
		mockNetworkAccess.EXPECT().GetUnauthorizedHttpClient().Return(mockHTTPClient).Times(1)

		engineConfig := configuration.New()
		engine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()

		mockDeriveEndpoint := func(pat string, config configuration.Configuration, client *http.Client, regions []string) (string, error) {
			return mockedPatEndpoint, nil
		}

		err := entryPointDI(mockInvocationContext, &logger, engine, authenticator, mockDeriveEndpoint)
		assert.NoError(t, err)

		assert.Empty(t, config.GetString(auth.CONFIG_KEY_OAUTH_TOKEN))
		assert.Empty(t, config.GetString(configuration.AUTHENTICATION_TOKEN))
	})

	t.Run("DeriveEndpointFromPAT fails", func(t *testing.T) {
		config := configuration.New()
		config.Set(authTypeParameter, auth.AUTH_TYPE_PAT)
		config.Set(ConfigurationNewAuthenticationToken, testPAT)
		originalToken := "original-token"
		config.Set(expectedAPIKeyStorage, originalToken)

		config.Set(configuration.SNYK_REGION_URLS, []string{"https://api.snyk.io"})

		mockInvocationContext := mocks.NewMockInvocationContext(mockCtl)
		mockInvocationContext.EXPECT().GetConfiguration().Return(config).AnyTimes()
		mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		mockInvocationContext.EXPECT().GetAnalytics().Return(analytics).Times(1)
		mockInvocationContext.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).Times(1)
		mockNetworkAccess.EXPECT().GetUnauthorizedHttpClient().Return(mockHTTPClient).Times(1)

		engineConfig := configuration.New()
		engine.EXPECT().GetConfiguration().Return(engineConfig).AnyTimes()

		expectedErr := errors.New("mocked DeriveEndpointFromPAT error")
		mockDeriveEndpoint := func(pat string, config configuration.Configuration, client *http.Client, regions []string) (string, error) {
			return "", expectedErr
		}

		err := entryPointDI(mockInvocationContext, &logger, engine, authenticator, mockDeriveEndpoint)
		assert.Error(t, err)
		assert.ErrorIs(t, err, expectedErr)

		assert.Equal(t, originalToken, config.GetString(expectedAPIKeyStorage))
	})
}

func Test_autodetectAuth(t *testing.T) {
	t.Run("in stable versions, token by default", func(t *testing.T) {
		expected := auth.AUTH_TYPE_OAUTH
		config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		config.Set(configuration.PREVIEW_FEATURES_ENABLED, false)
		actual := autoDetectAuthType(config)
		assert.Equal(t, expected, actual)
	})

	t.Run("token for IDEs", func(t *testing.T) {
		expected := auth.AUTH_TYPE_TOKEN
		config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		config.Set(configuration.INTEGRATION_NAME, "VS_CODE")
		actual := autoDetectAuthType(config)
		assert.Equal(t, expected, actual)
	})

	t.Run("token for given API token", func(t *testing.T) {
		expected := auth.AUTH_TYPE_TOKEN
		config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		config.Set(ConfigurationNewAuthenticationToken, "00000000-0000-0000-0000-000000000000")
		actual := autoDetectAuthType(config)
		assert.Equal(t, expected, actual)
	})

	t.Run("token for given PAT", func(t *testing.T) {
		expected := auth.AUTH_TYPE_PAT
		config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		config.Set(ConfigurationNewAuthenticationToken, "snyk_uat.12345678.abcdefg-hijklmnop.qrstuvwxyz-123456")
		actual := autoDetectAuthType(config)
		assert.Equal(t, expected, actual)
	})
}
