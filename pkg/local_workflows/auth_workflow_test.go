package localworkflows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/machineenrollment"
	"github.com/snyk/go-application-framework/pkg/mocks"
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

// Test_auth_clientPrivateKeyFile exercises the real authEntryPoint (not the DI'd one), end to end,
// to verify that setting --client-private-key-file makes it authenticate with a private_key_jwt
// client assertion instead of a client secret.
func Test_auth_clientPrivateKeyFile(t *testing.T) {
	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	keyFile := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, machineenrollment.WriteKeyFile(keyFile, key))

	var gotForm url.Values
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		gotForm = r.Form

		newToken := &oauth2.Token{
			AccessToken: "a",
			TokenType:   "bearer",
			Expiry:      time.Now().Add(60 * time.Second).UTC(),
		}
		data, marshalErr := json.Marshal(newToken)
		require.NoError(t, marshalErr)
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		_, writeErr := w.Write(data)
		require.NoError(t, writeErr)
	})

	mockCtl := gomock.NewController(t)
	logContent := &bytes.Buffer{}
	logger := zerolog.New(logContent)
	a := analytics.New()
	engine := mocks.NewMockEngine(mockCtl)
	networkAccess := mocks.NewMockNetworkAccess(mockCtl)

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, srv.URL)
	config.Set(auth.PARAMETER_CLIENT_ID, "machine-client-1")
	config.Set(ClientPrivateKeyFileParameter, keyFile)

	engine.EXPECT().GetConfiguration().Return(config).AnyTimes()
	networkAccess.EXPECT().GetUnauthorizedHttpClient().Return(http.DefaultClient).AnyTimes()

	mockInvocationContext := mocks.NewMockInvocationContext(mockCtl)
	mockInvocationContext.EXPECT().GetConfiguration().Return(config).AnyTimes()
	mockInvocationContext.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	mockInvocationContext.EXPECT().GetEngine().Return(engine).AnyTimes()
	mockInvocationContext.EXPECT().GetNetworkAccess().Return(networkAccess).AnyTimes()
	mockInvocationContext.EXPECT().GetAnalytics().Return(a).AnyTimes()

	_, err = authEntryPoint(mockInvocationContext, nil)
	require.NoError(t, err)

	assert.Equal(t, "machine-client-1", gotForm.Get("client_id"))
	assert.Equal(t, machineenrollment.ClientAssertionType, gotForm.Get("client_assertion_type"))
	assert.NotEmpty(t, gotForm.Get("client_assertion"))
	assert.Empty(t, gotForm.Get("client_secret"))
	assert.NotEmpty(t, config.GetString(auth.CONFIG_KEY_OAUTH_TOKEN))
}

func Test_auth_clientPrivateKeyFile_errors(t *testing.T) {
	newCtx := func(t *testing.T, config configuration.Configuration) *mocks.MockInvocationContext {
		t.Helper()
		mockCtl := gomock.NewController(t)
		logger := zerolog.New(&bytes.Buffer{})
		networkAccess := mocks.NewMockNetworkAccess(mockCtl)
		networkAccess.EXPECT().GetUnauthorizedHttpClient().Return(http.DefaultClient).AnyTimes()
		engine := mocks.NewMockEngine(mockCtl)
		engine.EXPECT().GetConfiguration().Return(config).AnyTimes()
		ictx := mocks.NewMockInvocationContext(mockCtl)
		ictx.EXPECT().GetConfiguration().Return(config).AnyTimes()
		ictx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
		ictx.EXPECT().GetEngine().Return(engine).AnyTimes()
		ictx.EXPECT().GetNetworkAccess().Return(networkAccess).AnyTimes()
		ictx.EXPECT().GetAnalytics().Return(analytics.New()).AnyTimes()
		return ictx
	}

	t.Run("missing client id", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ClientPrivateKeyFileParameter, "/some/key.pem")
		_, err := authEntryPoint(newCtx(t, config), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "--client-id")
	})

	t.Run("missing key file", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(auth.PARAMETER_CLIENT_ID, "c")
		config.Set(ClientPrivateKeyFileParameter, filepath.Join(t.TempDir(), "nope.pem"))
		_, err := authEntryPoint(newCtx(t, config), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nope.pem")
	})
}
