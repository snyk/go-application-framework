package localworkflows

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/machinecredential"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func Test_InitAuth_NoLongerOffersAClientPrivateKeyFile(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	require.NoError(t, InitAuth(engine))

	entry, ok := engine.GetWorkflow(WORKFLOWID_AUTH)
	require.True(t, ok)
	flags := workflow.FlagsetFromConfigurationOptions(entry.GetConfigurationOptions())
	assert.Nil(t, flags.Lookup("client-private-key-file"))
	assert.NotNil(t, flags.Lookup(auth.PARAMETER_CLIENT_ID))
}

func Test_AuthEntryPointDI_ClearsStoredTokensInLocalAndGlobalConfig(t *testing.T) {
	const pat = "snyk_uat.12345678.abcdefg-hijklmnop.qrstuvwxyz-123456"

	// The flows overwrite some of these keys after clearing them, so the cleared state is
	// asserted at the moment each flow starts authenticating, not only after it returns.
	assertCleared := func(t *testing.T, localConfig, globalConfig configuration.Configuration) {
		t.Helper()
		for name, config := range map[string]configuration.Configuration{"local": localConfig, "global": globalConfig} {
			assert.Empty(t, config.GetString(auth.CONFIG_KEY_OAUTH_TOKEN), "%s config oauth token", name)
			assert.Empty(t, config.GetString(configuration.AUTHENTICATION_TOKEN), "%s config authentication token", name)
			assert.Empty(t, config.GetString(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE), "%s config machine credential", name)
		}
	}

	testCases := []struct {
		name       string
		authType   string
		setupMocks func(t *testing.T, engine *mocks.MockEngine, authenticator *mocks.MockAuthenticator, localConfig, globalConfig configuration.Configuration)
		assertPost func(t *testing.T, localConfig, globalConfig configuration.Configuration)
	}{
		{
			name:     "OAuth flow",
			authType: auth.AUTH_TYPE_OAUTH,
			setupMocks: func(t *testing.T, _ *mocks.MockEngine, authenticator *mocks.MockAuthenticator, localConfig, globalConfig configuration.Configuration) {
				t.Helper()
				authenticator.EXPECT().Authenticate().DoAndReturn(func() error {
					assertCleared(t, localConfig, globalConfig)
					return nil
				})
			},
		},
		{
			name:     "PAT flow",
			authType: auth.AUTH_TYPE_PAT,
			setupMocks: func(t *testing.T, engine *mocks.MockEngine, _ *mocks.MockAuthenticator, localConfig, globalConfig configuration.Configuration) {
				t.Helper()
				engine.EXPECT().InvokeWithConfig(workflow.NewWorkflowIdentifier("whoami"), gomock.Any()).
					DoAndReturn(func(_ workflow.Identifier, _ configuration.Configuration) ([]workflow.Data, error) {
						assertCleared(t, localConfig, globalConfig)
						return nil, nil
					})
			},
			assertPost: func(t *testing.T, localConfig, globalConfig configuration.Configuration) {
				t.Helper()
				assert.Equal(t, pat, globalConfig.GetString(auth.CONFIG_KEY_TOKEN))
				assert.Empty(t, localConfig.GetString(auth.CONFIG_KEY_TOKEN))
			},
		},
		{
			name:     "legacy flow",
			authType: auth.AUTH_TYPE_TOKEN,
			setupMocks: func(t *testing.T, engine *mocks.MockEngine, _ *mocks.MockAuthenticator, localConfig, globalConfig configuration.Configuration) {
				t.Helper()
				engine.EXPECT().InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), gomock.Any()).
					DoAndReturn(func(_ workflow.Identifier, _ configuration.Configuration) ([]workflow.Data, error) {
						assertCleared(t, localConfig, globalConfig)
						return nil, nil
					})
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtl := gomock.NewController(t)
			logger := zerolog.New(&bytes.Buffer{})
			engine := mocks.NewMockEngine(mockCtl)
			authenticator := mocks.NewMockAuthenticator(mockCtl)

			localConfig := configuration.NewWithOpts()
			globalConfig := configuration.NewWithOpts()
			for _, config := range []configuration.Configuration{localConfig, globalConfig} {
				config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, "existing-oauth-token")
				config.Set(configuration.AUTHENTICATION_TOKEN, "existing-auth-token")
				config.Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, `{"client_id":"c","private_key_pem":"k"}`)
			}
			localConfig.Set(AuthTypeParameter, tc.authType)
			if tc.authType == auth.AUTH_TYPE_PAT {
				localConfig.Set(ConfigurationNewAuthenticationToken, pat)
			}

			engine.EXPECT().GetConfiguration().Return(globalConfig).AnyTimes()
			mockInvocationContext := mocks.NewMockInvocationContext(mockCtl)
			mockInvocationContext.EXPECT().GetConfiguration().Return(localConfig).AnyTimes()
			mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
			mockInvocationContext.EXPECT().GetAnalytics().Return(analytics.New()).AnyTimes()
			tc.setupMocks(t, engine, authenticator, localConfig, globalConfig)

			err := AuthEntryPointDI(mockInvocationContext, &logger, engine, authenticator)
			require.NoError(t, err)

			assertCleared(t, localConfig, globalConfig)
			if tc.assertPost != nil {
				tc.assertPost(t, localConfig, globalConfig)
			}
		})
	}
}

func Test_AuthEntryPointDI_OAuthFlow_CopiesNewOAuthTokenFromLocalToGlobalConfig(t *testing.T) {
	const newToken = "newly-obtained-oauth-token"

	mockCtl := gomock.NewController(t)
	logger := zerolog.New(&bytes.Buffer{})
	engine := mocks.NewMockEngine(mockCtl)
	authenticator := mocks.NewMockAuthenticator(mockCtl)

	localConfig := configuration.NewWithOpts()
	globalConfig := configuration.NewWithOpts()
	for _, config := range []configuration.Configuration{localConfig, globalConfig} {
		config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, "existing-oauth-token")
	}
	localConfig.Set(AuthTypeParameter, auth.AUTH_TYPE_OAUTH)

	engine.EXPECT().GetConfiguration().Return(globalConfig).AnyTimes()
	mockInvocationContext := mocks.NewMockInvocationContext(mockCtl)
	mockInvocationContext.EXPECT().GetConfiguration().Return(localConfig).AnyTimes()
	mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	mockInvocationContext.EXPECT().GetAnalytics().Return(analytics.New()).AnyTimes()
	authenticator.EXPECT().Authenticate().DoAndReturn(func() error {
		localConfig.Set(auth.CONFIG_KEY_OAUTH_TOKEN, newToken)
		return nil
	})

	err := AuthEntryPointDI(mockInvocationContext, &logger, engine, authenticator)
	require.NoError(t, err)

	assert.Equal(t, newToken, globalConfig.GetString(auth.CONFIG_KEY_OAUTH_TOKEN))
}
