package localworkflows

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/machinecredential"
	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/internal/machineenrollment/enrollmenttest"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/logging"
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

	t.Run("never machine, even with a client id", func(t *testing.T) {
		config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		config.Set(auth.PARAMETER_CLIENT_ID, "client-1")
		assert.NotEqual(t, authTypeMachine, autoDetectAuthType(config))
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

func Test_InitAuth_DescribesTheMachineAuthType(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	require.NoError(t, InitAuth(engine))

	entry, ok := engine.GetWorkflow(WORKFLOWID_AUTH)
	require.True(t, ok)
	flags := workflow.FlagsetFromConfigurationOptions(entry.GetConfigurationOptions())
	assert.Contains(t, flags.Lookup(AuthTypeParameter).Usage, authTypeMachine)
}

func Test_InitAuth_OffersAClientPrivateKeyAlongsideTheClientID(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	require.NoError(t, InitAuth(engine))

	entry, ok := engine.GetWorkflow(WORKFLOWID_AUTH)
	require.True(t, ok)
	flags := workflow.FlagsetFromConfigurationOptions(entry.GetConfigurationOptions())
	assert.NotNil(t, flags.Lookup(machinecredential.CONFIG_KEY_CLIENT_PRIVATE_KEY))
	assert.Contains(t, flags.Lookup(AuthTypeParameter).Usage, "--"+machinecredential.CONFIG_KEY_CLIENT_PRIVATE_KEY)
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

func newMachineAuthEnv(t *testing.T) *enrollEnv {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	server := enrollmenttest.NewServer(t)
	config := openFileBackedConfig()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)

	engine := workflow.NewWorkFlowEngine(config)
	require.NoError(t, InitAuth(engine))
	require.NoError(t, engine.Init())
	return &enrollEnv{home: home, server: server, engine: engine, config: config}
}

// issueMachineCredential registers a client with the fake service, as enrolling elsewhere does, and
// returns its client id and the PEM of its key.
func issueMachineCredential(t *testing.T, server *enrollmenttest.Server, clientID string) []byte {
	t.Helper()
	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	server.RegisterClient(clientID, &key.PublicKey)
	keyPEM, err := machineenrollment.EncodeKeyPEM(key)
	require.NoError(t, err)
	return keyPEM
}

// storeUserTokens stores the token of each kind of user login, with the alternative keys a host such
// as the Snyk CLI registers for the API token.
func (e *enrollEnv) storeUserTokens(t *testing.T) map[string]string {
	t.Helper()
	e.config.AddAlternativeKeys(configuration.AUTHENTICATION_TOKEN, []string{"snyk_cfg_api", auth.CONFIG_KEY_TOKEN})
	tokens := map[string]string{
		auth.CONFIG_KEY_OAUTH_TOKEN:        e.storeUserToken(t),
		configuration.AUTHENTICATION_TOKEN: "00000000-0000-0000-0000-000000000000",
		auth.CONFIG_KEY_TOKEN:              "snyk_uat.12345678.abcdefg-hijklmnop.qrstuvwxyz-123456",
	}
	for _, key := range []string{configuration.AUTHENTICATION_TOKEN, auth.CONFIG_KEY_TOKEN} {
		e.config.PersistInStorage(key)
		e.config.Set(key, tokens[key])
	}
	return tokens
}

func (e *enrollEnv) importMachineCredential(t *testing.T, clientID string, keyPEM []byte) error {
	t.Helper()
	invokeConfig := e.config.Clone()
	invokeConfig.Set(AuthTypeParameter, authTypeMachine)
	if clientID != "" {
		invokeConfig.Set(auth.PARAMETER_CLIENT_ID, clientID)
	}
	if keyPEM != nil {
		invokeConfig.Set(machinecredential.CONFIG_KEY_CLIENT_PRIVATE_KEY, string(keyPEM))
	}
	_, err := e.engine.InvokeWithConfig(WORKFLOWID_AUTH, invokeConfig)
	return err
}

func Test_auth_machine_importedCredentialKeepsAuthenticatingNewProcessesAfterTheTokenExpires(t *testing.T) {
	env := newMachineAuthEnv(t)
	keyPEM := issueMachineCredential(t, env.server, "client-imported")

	require.NoError(t, env.importMachineCredential(t, "client-imported", keyPEM))

	require.Equal(t, http.StatusOK, env.whoamiInNewProcess(t))
	tokensAfterFirstRun := env.server.TokenRequests
	env.expireStoredAccessToken(t)
	assert.Equal(t, http.StatusOK, env.whoamiInNewProcess(t))
	assert.Equal(t, tokensAfterFirstRun+1, env.server.TokenRequests, "a new token was minted from the stored key")
	assert.Equal(t, 0, env.server.EnrollmentRequests(), "importing does not enroll")
	stored, err := machinecredential.Load(openFileBackedConfig())
	require.NoError(t, err)
	assert.Equal(t, "client-imported", stored.ClientID)
}

func Test_auth_machine_credentialTheServiceRejectsIsReportedAndStoresNothing(t *testing.T) {
	rejected := map[string]func(t *testing.T, env *enrollEnv) (string, []byte){
		"unknown client id": func(t *testing.T, env *enrollEnv) (string, []byte) {
			t.Helper()
			return "client-unknown", issueMachineCredential(t, env.server, "client-other")
		},
		"key of another client": func(t *testing.T, env *enrollEnv) (string, []byte) {
			t.Helper()
			issueMachineCredential(t, env.server, "client-a")
			return "client-a", issueMachineCredential(t, env.server, "client-b")
		},
	}
	for name, credentialFor := range rejected {
		t.Run(name+", user tokens kept", func(t *testing.T) {
			env := newMachineAuthEnv(t)
			userTokens := env.storeUserTokens(t)
			clientID, keyPEM := credentialFor(t, env)

			err := env.importMachineCredential(t, clientID, keyPEM)

			require.Error(t, err)
			assert.ErrorContains(t, err, "failed authenticating as client "+clientID)
			assert.ErrorContains(t, err, "invalid_client", "the service's reason is kept")
			assertNothingStored(t, env.home)
			stored := env.storedValues(t)
			for key, token := range userTokens {
				assert.Equal(t, token, stored[key], key)
			}
		})
		t.Run(name+", machine credential kept", func(t *testing.T) {
			env := newMachineAuthEnv(t)
			require.NoError(t, env.importMachineCredential(t, "client-first", issueMachineCredential(t, env.server, "client-first")))
			clientID, keyPEM := credentialFor(t, env)

			err := env.importMachineCredential(t, clientID, keyPEM)

			require.Error(t, err)
			stored, loadErr := machinecredential.Load(openFileBackedConfig())
			require.NoError(t, loadErr)
			assert.Equal(t, "client-first", stored.ClientID)
			assert.Equal(t, http.StatusOK, env.whoamiInNewProcess(t))
		})
	}
}

func Test_auth_machine_repeatImportReplacesTheCredential(t *testing.T) {
	env := newMachineAuthEnv(t)
	require.NoError(t, env.importMachineCredential(t, "client-first", issueMachineCredential(t, env.server, "client-first")))
	env.server.RevokeClient("client-first")

	require.NoError(t, env.importMachineCredential(t, "client-second", issueMachineCredential(t, env.server, "client-second")))

	stored, err := machinecredential.Load(openFileBackedConfig())
	require.NoError(t, err)
	assert.Equal(t, "client-second", stored.ClientID)
	assert.Equal(t, http.StatusOK, env.whoamiInNewProcess(t))
}

func Test_auth_machine_unusableStorageFailsBeforeAnyNetworkCall(t *testing.T) {
	breakages := map[string]func(t *testing.T, env *enrollEnv){
		"no storage": func(t *testing.T, env *enrollEnv) {
			t.Helper()
			env.config.SetStorage(nil)
		},
		"storage that persists nothing": func(t *testing.T, env *enrollEnv) {
			t.Helper()
			env.config.SetStorage(&configuration.EmptyStorage{})
		},
		"configuration path is a directory": func(t *testing.T, env *enrollEnv) {
			t.Helper()
			require.NoError(t, os.MkdirAll(filepath.Join(env.configDir(), "snyk.json"), 0o755))
		},
	}
	for name, breakStorage := range breakages {
		t.Run(name, func(t *testing.T) {
			env := newMachineAuthEnv(t)
			keyPEM := issueMachineCredential(t, env.server, "client-1")
			breakStorage(t, env)

			err := env.importMachineCredential(t, "client-1", keyPEM)

			require.Error(t, err)
			assert.ErrorContains(t, err, "credential cannot be stored")
			assert.Equal(t, 0, env.server.TokenRequests, "no token was minted")
		})
	}
}

func Test_auth_machine_missingKeyFailsAndStoresNothing(t *testing.T) {
	env := newMachineAuthEnv(t)
	issueMachineCredential(t, env.server, "client-1")

	err := env.importMachineCredential(t, "client-1", nil)

	require.Error(t, err)
	assert.ErrorContains(t, err, "--"+machinecredential.CONFIG_KEY_CLIENT_PRIVATE_KEY)
	assert.Equal(t, 0, env.server.TokenRequests)
	assertNothingStored(t, env.home)
}

func Test_auth_machine_missingClientIDFailsAndStoresNothing(t *testing.T) {
	env := newMachineAuthEnv(t)
	keyPEM := issueMachineCredential(t, env.server, "client-1")

	err := env.importMachineCredential(t, "", keyPEM)

	require.Error(t, err)
	assert.ErrorContains(t, err, "--"+auth.PARAMETER_CLIENT_ID)
	assert.ErrorContains(t, err, "--"+AuthTypeParameter+"="+authTypeMachine)
	assert.Equal(t, 0, env.server.TokenRequests)
	assertNothingStored(t, env.home)
}

func pemOf(t *testing.T, blockType string, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

func Test_auth_machine_unusableKeyFailsWithoutRevealingIt(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p384DER, err := x509.MarshalPKCS8PrivateKey(p384Key)
	require.NoError(t, err)
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	corruptDER := slices.Clone(pkcs8DER)
	corruptDER[len(corruptDER)/2] ^= 0xff

	keys := map[string][]byte{
		"not PEM":          []byte("this is not a key at all, just some text on stdin"),
		"PKCS1 RSA key":    pemOf(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)),
		"P-384 key":        pemOf(t, "PRIVATE KEY", p384DER),
		"corrupt PKCS8":    pemOf(t, "PRIVATE KEY", corruptDER),
		"truncated PKCS8":  pemOf(t, "PRIVATE KEY", pkcs8DER[:len(pkcs8DER)/2]),
		"public key block": pemOf(t, "PUBLIC KEY", x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)),
	}
	for name, keyPEM := range keys {
		t.Run(name, func(t *testing.T) {
			env := newMachineAuthEnv(t)
			logs := &bytes.Buffer{}
			logger := zerolog.New(logs)
			env.engine.SetLogger(&logger)

			err := env.importMachineCredential(t, "client-1", keyPEM)

			require.Error(t, err)
			assert.ErrorContains(t, err, "the machine client key cannot be used")
			assert.Equal(t, 0, env.server.TokenRequests)
			assertNothingStored(t, env.home)
			for _, line := range strings.Split(string(keyPEM), "\n") {
				if line = strings.TrimSpace(line); len(line) >= 16 && !strings.HasPrefix(line, "-----") {
					assert.NotContains(t, err.Error(), line)
					assert.NotContains(t, logs.String(), line)
				}
			}
		})
	}
}

func Test_auth_machine_importNeverLogsTheKeyAndLaterLogsRedactIt(t *testing.T) {
	env := newMachineAuthEnv(t)
	logs := &bytes.Buffer{}
	logger := zerolog.New(logs).Level(zerolog.TraceLevel)
	env.engine.SetLogger(&logger)
	keyPEM := issueMachineCredential(t, env.server, "client-1")

	require.NoError(t, env.importMachineCredential(t, "client-1", keyPEM))

	assert.Contains(t, logs.String(), "Authentication Type: machine", "the import was logged")
	scrubDict := logging.GetScrubDictFromConfig(openFileBackedConfig())
	for _, line := range strings.Split(string(keyPEM), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "-----") {
			assert.NotContains(t, logs.String(), line)
			if len(line) >= 16 {
				assert.Contains(t, scrubDict, line, "a process started afterwards redacts the stored key")
			}
		}
	}
}

func Test_auth_machine_theEnginesOwnConfigurationSeesTheCredential(t *testing.T) {
	env := newMachineAuthEnv(t)

	require.NoError(t, env.importMachineCredential(t, "client-1", issueMachineCredential(t, env.server, "client-1")))

	credential, err := machinecredential.Load(env.engine.GetConfiguration())
	require.NoError(t, err, "a host that authenticates in the same process sees the credential")
	assert.Equal(t, "client-1", credential.ClientID)
}

func Test_auth_machine_removesTheStoredUserTokensLikeALogin(t *testing.T) {
	env := newMachineAuthEnv(t)
	userTokens := env.storeUserTokens(t)

	require.NoError(t, env.importMachineCredential(t, "client-1", issueMachineCredential(t, env.server, "client-1")))

	stored := env.storedValues(t)
	for key := range userTokens {
		assert.NotContains(t, stored, key, "the machine credential is the only stored identity")
		assert.Empty(t, env.engine.GetConfiguration().GetString(key), "the engine's own configuration no longer holds %s", key)
	}
	assert.Contains(t, stored, machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE)
	require.Equal(t, http.StatusOK, env.whoamiInNewProcess(t))
	assert.Equal(t, []string{"token-client-1-2"}, env.server.BearerTokens(), "the next process authenticates as the machine")
}

func Test_importMachineCredential_refusesAKeyOverTheSizeCapBeforeAnythingElse(t *testing.T) {
	for name, tt := range map[string]struct {
		size    int
		wantErr string
	}{
		"at the cap":   {size: maxMachineKeySize, wantErr: "cannot be used"},
		"over the cap": {size: maxMachineKeySize + 1, wantErr: "larger than"},
	} {
		t.Run(name, func(t *testing.T) {
			config := configuration.NewWithOpts()
			config.Set(auth.PARAMETER_CLIENT_ID, "client-1")
			config.Set(machinecredential.CONFIG_KEY_CLIENT_PRIVATE_KEY, strings.Repeat("A", tt.size))
			invocationCtx := mocks.NewMockInvocationContext(gomock.NewController(t))
			logger := zerolog.Nop()

			err := importMachineCredential(invocationCtx, &logger, config, config)

			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}
