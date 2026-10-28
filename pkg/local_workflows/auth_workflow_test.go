package localworkflows

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/machinecredential"
	"github.com/snyk/go-application-framework/internal/machineenrollment"
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

func Test_AuthEntryPointDI_FailedDeleteAfterTheLoginReportsTheCredentialIsStillStored(t *testing.T) {
	mockCtl := gomock.NewController(t)
	logs := &bytes.Buffer{}
	logger := zerolog.New(logs)
	engine := mocks.NewMockEngine(mockCtl)
	authenticator := mocks.NewMockAuthenticator(mockCtl)

	deleteErr := errors.New("disk full")
	storage := mocks.NewMockStorage(mockCtl)
	storage.EXPECT().Lock(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	storage.EXPECT().Unlock().Return(nil).AnyTimes()
	storage.EXPECT().Refresh(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	storageCheck := storage.EXPECT().Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, gomock.Any()).Return(nil)
	storage.EXPECT().Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, gomock.Any()).Return(deleteErr).AnyTimes().After(storageCheck)
	storage.EXPECT().Set(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	localConfig := configuration.NewWithOpts()
	globalConfig := configuration.NewWithOpts()
	localConfig.SetStorage(storage)
	globalConfig.SetStorage(storage)
	localConfig.Set(AuthTypeParameter, auth.AUTH_TYPE_OAUTH)
	secret := `{"client_id":"c","private_key_pem":"super-secret-key-material"}`
	localConfig.Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, secret)

	engine.EXPECT().GetConfiguration().Return(globalConfig).AnyTimes()
	invocationCtx := mocks.NewMockInvocationContext(mockCtl)
	invocationCtx.EXPECT().GetConfiguration().Return(localConfig).AnyTimes()
	invocationCtx.EXPECT().GetAnalytics().Return(analytics.New()).AnyTimes()
	authenticator.EXPECT().Authenticate().Return(nil).Times(1)
	engine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

	err := AuthEntryPointDI(invocationCtx, &logger, engine, authenticator)

	require.ErrorIs(t, err, deleteErr)
	assert.ErrorContains(t, err, "login succeeded")
	assert.ErrorContains(t, err, "machine credential is still stored")
	assert.Equal(t, secret, localConfig.GetString(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE), "the credential that will be used stays visible")
	assert.NotContains(t, err.Error(), "super-secret-key-material")
	assert.NotContains(t, logs.String(), "super-secret-key-material")
}

func Test_AuthEntryPointDI_NothingStoredLeavesTheStorageUntouched(t *testing.T) {
	mockCtl := gomock.NewController(t)
	logger := zerolog.New(&bytes.Buffer{})
	engine := mocks.NewMockEngine(mockCtl)
	authenticator := mocks.NewMockAuthenticator(mockCtl)

	storage := mocks.NewMockStorage(mockCtl)
	storage.EXPECT().Set(gomock.Any(), gomock.Any()).DoAndReturn(func(key string, _ any) error {
		assert.NotEqual(t, machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, key, "nothing stored, so nothing to clear")
		return nil
	}).AnyTimes()
	storage.EXPECT().Lock(gomock.Any(), gomock.Any()).Times(0)
	localConfig := configuration.NewWithOpts()
	globalConfig := configuration.NewWithOpts()
	localConfig.SetStorage(storage)
	globalConfig.SetStorage(storage)
	localConfig.Set(AuthTypeParameter, auth.AUTH_TYPE_OAUTH)

	engine.EXPECT().GetConfiguration().Return(globalConfig).AnyTimes()
	invocationCtx := mocks.NewMockInvocationContext(mockCtl)
	invocationCtx.EXPECT().GetConfiguration().Return(localConfig).AnyTimes()
	invocationCtx.EXPECT().GetAnalytics().Return(analytics.New()).AnyTimes()
	authenticator.EXPECT().Authenticate().Return(nil).Times(1)

	require.NoError(t, AuthEntryPointDI(invocationCtx, &logger, engine, authenticator))
}

type enrolledAuthEnv struct {
	localConfig, globalConfig   configuration.Configuration
	localStorage, globalStorage configuration.Storage
	engine                      *mocks.MockEngine
	authenticator               *mocks.MockAuthenticator
	invocationCtx               *mocks.MockInvocationContext
	logger                      zerolog.Logger
}

// The local configuration is file-backed, so its clones re-read the file.
func newEnrolledAuthEnv(t *testing.T, authType string) *enrolledAuthEnv {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	mockCtl := gomock.NewController(t)
	env := &enrolledAuthEnv{
		localConfig:   openFileBackedConfig(),
		globalConfig:  configuration.NewWithOpts(),
		globalStorage: configuration.NewJsonStorage(filepath.Join(t.TempDir(), "snyk.json")),
		engine:        mocks.NewMockEngine(mockCtl),
		authenticator: mocks.NewMockAuthenticator(mockCtl),
		invocationCtx: mocks.NewMockInvocationContext(mockCtl),
		logger:        zerolog.New(&bytes.Buffer{}),
	}
	env.localStorage = env.localConfig.GetStorage()
	env.globalConfig.SetStorage(env.globalStorage)
	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	for _, config := range []configuration.Configuration{env.localConfig, env.globalConfig} {
		require.NoError(t, machinecredential.Save(t.Context(), config, machinecredential.Credential{ClientID: "client-1", Key: key}))
	}
	env.localConfig.Set(AuthTypeParameter, authType)
	if authType == auth.AUTH_TYPE_PAT {
		env.localConfig.Set(ConfigurationNewAuthenticationToken, "snyk_uat.12345678.abcdefg-hijklmnop.qrstuvwxyz-123456")
	}

	env.engine.EXPECT().GetConfiguration().Return(env.globalConfig).AnyTimes()
	env.invocationCtx.EXPECT().GetConfiguration().Return(env.localConfig).AnyTimes()
	env.invocationCtx.EXPECT().GetEnhancedLogger().Return(&env.logger).AnyTimes()
	env.invocationCtx.EXPECT().GetAnalytics().Return(analytics.New()).AnyTimes()
	return env
}

func (e *enrolledAuthEnv) run() error {
	return AuthEntryPointDI(e.invocationCtx, &e.logger, e.engine, e.authenticator)
}

// loadStoredCredential reads the machine credential from storage alone, ignoring any in-memory view.
func loadStoredCredential(t *testing.T, storage configuration.Storage) error {
	t.Helper()
	fresh := configuration.NewWithOpts()
	require.NoError(t, storage.Refresh(fresh, machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE))
	_, err := machinecredential.Load(fresh)
	return err
}

func (e *enrolledAuthEnv) assertCredentialKept(t *testing.T) {
	t.Helper()
	assert.NoError(t, loadStoredCredential(t, e.localStorage), "local storage")
	assert.NoError(t, loadStoredCredential(t, e.globalStorage), "global storage")
	for name, config := range map[string]configuration.Configuration{"local": e.localConfig, "global": e.globalConfig} {
		_, err := machinecredential.Load(config)
		assert.NoError(t, err, "%s configuration still authenticates as the machine", name)
	}
}

func Test_AuthEntryPointDI_FailedPATValidationKeepsTheMachineCredential(t *testing.T) {
	env := newEnrolledAuthEnv(t, auth.AUTH_TYPE_PAT)
	validationErr := errors.New("invalid pat")
	env.engine.EXPECT().InvokeWithConfig(workflow.NewWorkflowIdentifier("whoami"), gomock.Any()).
		DoAndReturn(func(_ workflow.Identifier, validationConfig configuration.Configuration) ([]workflow.Data, error) {
			_, loadErr := machinecredential.Load(validationConfig)
			assert.ErrorIs(t, loadErr, machinecredential.ErrNotEnrolled, "the PAT is validated without the machine credential")
			return nil, validationErr
		})

	err := env.run()

	require.ErrorIs(t, err, validationErr)
	env.assertCredentialKept(t)
}

func Test_AuthEntryPointDI_FailedOAuthLoginKeepsTheMachineCredential(t *testing.T) {
	for name, loginErr := range map[string]error{
		"failed":   errors.New("oauth failure"),
		"canceled": context.Canceled,
	} {
		t.Run(name, func(t *testing.T) {
			env := newEnrolledAuthEnv(t, auth.AUTH_TYPE_OAUTH)
			env.authenticator.EXPECT().Authenticate().Return(loginErr)

			err := env.run()

			require.ErrorIs(t, err, loginErr)
			env.assertCredentialKept(t)
		})
	}
}

func Test_AuthEntryPointDI_PanickingLoginKeepsTheMachineCredential(t *testing.T) {
	testCases := map[string]func(env *enrolledAuthEnv){
		auth.AUTH_TYPE_OAUTH: func(env *enrolledAuthEnv) {
			env.authenticator.EXPECT().Authenticate().DoAndReturn(func() error { panic("login crashed") })
		},
		auth.AUTH_TYPE_PAT: func(env *enrolledAuthEnv) {
			env.engine.EXPECT().InvokeWithConfig(workflow.NewWorkflowIdentifier("whoami"), gomock.Any()).
				DoAndReturn(func(workflow.Identifier, configuration.Configuration) ([]workflow.Data, error) {
					panic("validation crashed")
				})
		},
	}
	for authType, makeLoginPanic := range testCases {
		t.Run(authType, func(t *testing.T) {
			env := newEnrolledAuthEnv(t, authType)
			makeLoginPanic(env)

			assert.Panics(t, func() { _ = env.run() }) //nolint:errcheck // the login panics before an error exists

			env.assertCredentialKept(t)
		})
	}
}

func Test_AuthEntryPointDI_SuccessfulLoginDeletesTheMachineCredential(t *testing.T) {
	for _, authType := range []string{auth.AUTH_TYPE_OAUTH, auth.AUTH_TYPE_PAT, auth.AUTH_TYPE_TOKEN} {
		t.Run(authType, func(t *testing.T) {
			env := newEnrolledAuthEnv(t, authType)
			env.authenticator.EXPECT().Authenticate().Return(nil).AnyTimes()
			env.engine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

			require.NoError(t, env.run())

			assert.ErrorIs(t, loadStoredCredential(t, env.localStorage), machinecredential.ErrNotEnrolled, "local storage")
			assert.ErrorIs(t, loadStoredCredential(t, env.globalStorage), machinecredential.ErrNotEnrolled, "global storage")
		})
	}
}

func Test_AuthEntryPointDI_UnusableCredentialStorageStopsBeforeTheLogin(t *testing.T) {
	cause := errors.New("storage failure")
	testCases := []struct {
		name         string
		configName   string
		breakStorage func(storage *mocks.MockStorage)
	}{
		{
			name:       "local storage cannot be locked",
			configName: "local",
			breakStorage: func(storage *mocks.MockStorage) {
				storage.EXPECT().Lock(gomock.Any(), gomock.Any()).Return(cause).AnyTimes()
			},
		},
		{
			name:       "global storage cannot be read",
			configName: "global",
			breakStorage: func(storage *mocks.MockStorage) {
				storage.EXPECT().Lock(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
				storage.EXPECT().Unlock().Return(nil).AnyTimes()
				storage.EXPECT().Refresh(gomock.Any(), gomock.Any()).Return(cause).AnyTimes()
			},
		},
	}

	for _, tc := range testCases {
		for _, authType := range []string{auth.AUTH_TYPE_OAUTH, auth.AUTH_TYPE_PAT} {
			t.Run(tc.name+" "+authType, func(t *testing.T) {
				env := newEnrolledAuthEnv(t, authType)
				brokenConfig, healthyStorage := env.localConfig, env.globalStorage
				if tc.configName == "global" {
					brokenConfig, healthyStorage = env.globalConfig, env.localStorage
				}
				brokenStorage := mocks.NewMockStorage(gomock.NewController(t))
				tc.breakStorage(brokenStorage)
				brokenConfig.SetStorage(brokenStorage)
				env.authenticator.EXPECT().Authenticate().Times(0)
				env.engine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any()).Times(0)

				err := env.run()

				require.ErrorIs(t, err, cause)
				assert.ErrorContains(t, err, tc.configName+" configuration")
				assert.NoError(t, loadStoredCredential(t, healthyStorage), "the other storage keeps the credential")
			})
		}
	}
}

func Test_AuthTypeOf(t *testing.T) {
	newConfig := func() configuration.Configuration {
		return configuration.NewWithOpts()
	}

	t.Run("the type that was asked for wins over what would be detected", func(t *testing.T) {
		config := newConfig()
		config.Set(ConfigurationNewAuthenticationToken, "00000000-0000-0000-0000-000000000000")
		config.Set(AuthTypeParameter, auth.AUTH_TYPE_PAT)
		assert.Equal(t, auth.AUTH_TYPE_PAT, AuthTypeOf(config))
	})

	t.Run("an unknown type is returned as it was asked for", func(t *testing.T) {
		config := newConfig()
		config.Set(AuthTypeParameter, "something-else")
		assert.Equal(t, "something-else", AuthTypeOf(config))
	})

	t.Run("detects the type when none was asked for", func(t *testing.T) {
		assert.Equal(t, auth.AUTH_TYPE_OAUTH, AuthTypeOf(newConfig()))

		ide := newConfig()
		ide.Set(configuration.INTEGRATION_NAME, "VS_CODE")
		assert.Equal(t, auth.AUTH_TYPE_TOKEN, AuthTypeOf(ide))

		token := newConfig()
		token.Set(ConfigurationNewAuthenticationToken, "00000000-0000-0000-0000-000000000000")
		assert.Equal(t, auth.AUTH_TYPE_TOKEN, AuthTypeOf(token))
	})
}
