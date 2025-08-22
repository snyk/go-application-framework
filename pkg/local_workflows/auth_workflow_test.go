package localworkflows

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/stretchr/testify/assert"
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
	engine.EXPECT().GetConfiguration().Return(config).AnyTimes()
	err := InitAuth(engine)
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	t.Run("happy", func(t *testing.T) {
		config.Set(AuthTypeParameter, nil)
		authenticator.EXPECT().Authenticate().Times(2).Return(nil)
		mockInvocationContext := mocks.NewMockInvocationContext(mockCtl)
		mockInvocationContext.EXPECT().GetConfiguration().Return(config).AnyTimes()
		mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		mockInvocationContext.EXPECT().GetAnalytics().Return(analytics).AnyTimes()
		err = AuthEntryPointDI(mockInvocationContext, &logger, engine, authenticator)
		err = AuthEntryPointDI(mockInvocationContext, &logger, engine, authenticator)
		assert.NoError(t, err)
	})

	t.Run("unhappy", func(t *testing.T) {
		config.Set(AuthTypeParameter, nil)
		expectedErr := fmt.Errorf("someting went wrong")
		authenticator.EXPECT().Authenticate().Times(1).Return(expectedErr)
		mockInvocationContext := mocks.NewMockInvocationContext(mockCtl)
		mockInvocationContext.EXPECT().GetConfiguration().Return(config).AnyTimes()
		mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		mockInvocationContext.EXPECT().GetAnalytics().Return(analytics).AnyTimes()
		err = AuthEntryPointDI(mockInvocationContext, &logger, engine, authenticator)
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

	engine.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	engine.EXPECT().Init().Times(1)
	engine.EXPECT().GetConfiguration().Return(config).AnyTimes()
	err := InitAuth(engine)
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	t.Run("happy", func(t *testing.T) {
		config.Set(AuthTypeParameter, auth.AUTH_TYPE_TOKEN)
		engine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any())
		mockInvocationContext := mocks.NewMockInvocationContext(mockCtl)
		mockInvocationContext.EXPECT().GetConfiguration().Return(config).AnyTimes()
		mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		mockInvocationContext.EXPECT().GetAnalytics().Return(analytics).AnyTimes()

		err = AuthEntryPointDI(mockInvocationContext, &logger, engine, authenticator)
		assert.NoError(t, err)
	})

	t.Run("automatically switch to token when API token is given", func(t *testing.T) {
		config.Set(AuthTypeParameter, nil)
		config.Set(ConfigurationNewAuthenticationToken, "00000000-0000-0000-0000-000000000000")
		engine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any())
		mockInvocationContext := mocks.NewMockInvocationContext(mockCtl)
		mockInvocationContext.EXPECT().GetConfiguration().Return(config).AnyTimes()
		mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		mockInvocationContext.EXPECT().GetAnalytics().Return(analytics).AnyTimes()

		err = AuthEntryPointDI(mockInvocationContext, &logger, engine, authenticator)
		assert.NoError(t, err)
	})
}

func Test_pat(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	logContent := &bytes.Buffer{}
	logger := zerolog.New(logContent)
	analytics := analytics.New()

	engine := mocks.NewMockEngine(mockCtl)
	authenticator := mocks.NewMockAuthenticator(mockCtl)
	pat := "myPAT"

	t.Run("happy", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(AuthTypeParameter, auth.AUTH_TYPE_PAT)
		config.Set(ConfigurationNewAuthenticationToken, pat)

		config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, "some-oauth-token")
		config.Set(configuration.AUTHENTICATION_TOKEN, "some-legacy-api-token")

		mockInvocationContext := mocks.NewMockInvocationContext(mockCtl)
		mockInvocationContext.EXPECT().GetConfiguration().Return(config).AnyTimes()
		mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		mockInvocationContext.EXPECT().GetAnalytics().Return(analytics).Times(1)

		engine.EXPECT().GetConfiguration().Return(config).AnyTimes()
		engine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any())

		err := AuthEntryPointDI(mockInvocationContext, &logger, engine, authenticator)
		assert.NoError(t, err)

		assert.Empty(t, config.GetString(auth.CONFIG_KEY_OAUTH_TOKEN))
		assert.Empty(t, config.GetString(configuration.AUTHENTICATION_TOKEN))
	})

	t.Run("invalid pat should fail", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(AuthTypeParameter, auth.AUTH_TYPE_PAT)
		config.Set(ConfigurationNewAuthenticationToken, pat)

		config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, "some-oauth-token")
		config.Set(configuration.AUTHENTICATION_TOKEN, "some-legacy-api-token")

		mockInvocationContext := mocks.NewMockInvocationContext(mockCtl)
		mockInvocationContext.EXPECT().GetConfiguration().Return(config).AnyTimes()
		mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		mockInvocationContext.EXPECT().GetAnalytics().Return(analytics).Times(1)

		engine.EXPECT().GetConfiguration().Return(config).AnyTimes()

		mockWhoAmIError := fmt.Errorf("mock whoami failure")
		engine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any()).Return(nil, mockWhoAmIError)

		err := AuthEntryPointDI(mockInvocationContext, &logger, engine, authenticator)
		assert.ErrorIs(t, err, mockWhoAmIError)

		assert.Empty(t, config.GetString(auth.CONFIG_KEY_OAUTH_TOKEN))
		assert.Empty(t, config.GetString(configuration.AUTHENTICATION_TOKEN))
	})
}

func Test_clearAllCredentialsBeforeAuth(t *testing.T) {
	mockCtl := gomock.NewController(t)
	defer mockCtl.Finish()

	logContent := &bytes.Buffer{}
	logger := zerolog.New(logContent)
	analytics := analytics.New()
	engine := mocks.NewMockEngine(mockCtl)
	authenticator := mocks.NewMockAuthenticator(mockCtl)
	engine.EXPECT().GetConfiguration().Return(configuration.NewWithOpts()).AnyTimes()
	testCases := []struct {
		name       string
		authType   string
		setupMocks func()
	}{
		{
			name:     "OAuth flow clears all credentials",
			authType: auth.AUTH_TYPE_OAUTH,
			setupMocks: func() {
				authenticator.EXPECT().Authenticate().Return(nil)
			},
		},
		{
			name:     "PAT flow clears all credentials",
			authType: auth.AUTH_TYPE_PAT,
			setupMocks: func() {
				engine.EXPECT().GetConfiguration().Return(configuration.NewWithOpts()).AnyTimes()
				engine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any()).Return(nil, nil)
			},
		},
		{
			name:     "Token flow clears all credentials",
			authType: auth.AUTH_TYPE_TOKEN,
			setupMocks: func() {
				engine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any()).Return(nil, nil)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := configuration.NewWithOpts()
			config.Set(AuthTypeParameter, tc.authType)
			if tc.authType == auth.AUTH_TYPE_PAT {
				config.Set(ConfigurationNewAuthenticationToken, "snyk_uat.12345678.abcdefg-hijklmnop.qrstuvwxyz-123456")
			}

			// Set existing tokens that should be cleared
			config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, "existing-oauth-token")
			config.Set(configuration.AUTHENTICATION_TOKEN, "existing-auth-token")

			mockInvocationContext := mocks.NewMockInvocationContext(mockCtl)
			mockInvocationContext.EXPECT().GetConfiguration().Return(config).AnyTimes()
			mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
			mockInvocationContext.EXPECT().GetAnalytics().Return(analytics).AnyTimes()

			tc.setupMocks()

			err := AuthEntryPointDI(mockInvocationContext, &logger, engine, authenticator)
			assert.NoError(t, err)

			// Verify both tokens are cleared regardless of auth type
			assert.Empty(t, config.GetString(auth.CONFIG_KEY_OAUTH_TOKEN), "OAuth token should be cleared for %s flow", tc.authType)
			assert.Empty(t, config.GetString(configuration.AUTHENTICATION_TOKEN), "Authentication token should be cleared for %s flow", tc.authType)
		})
	}
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
