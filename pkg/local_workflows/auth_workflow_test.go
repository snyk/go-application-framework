package localworkflows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/h2non/gock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func logMiddleware(t *testing.T, handler http.Handler) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Mock Server request: %s %s %s\n", r.Method, r.URL.Path, r.URL.Query())
		handler.ServeHTTP(w, r) // Call the actual handler
	})
}

func headlessOpenBrowserFunc(t *testing.T) func(url string) {
	t.Helper()
	return func(url string) {
		fmt.Println("Mock opening browser...", url)
		_, err := http.DefaultClient.Get(url)
		if err != nil {
			fmt.Println("Error opening browser:", err)
		}
	}
}

func Test_auth_oauth(t *testing.T) {
	mockCtl := gomock.NewController(t)
	logContent := &bytes.Buffer{}

	logger := zerolog.New(logContent)
	engine := mocks.NewMockEngine(mockCtl)

	engine.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	engine.EXPECT().Init().Times(1)

	err := InitAuth(engine)
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	t.Run("happy", func(t *testing.T) {
		config := configuration.NewInMemory()
		config.Set(authTypeParameter, nil)

		// Create mock server for successful oauth2 flow
		mux := http.NewServeMux()
		mux.HandleFunc("/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) {
			// Redirect to the redirect_uri with a mock authorization code
			redirectURI := r.URL.Query().Get("redirect_uri")
			state := r.URL.Query().Get("state")
			http.Redirect(w, r, redirectURI+"?code=mock-auth-code&state="+state, http.StatusFound)
		})
		mux.HandleFunc("/oauth2/token", mockOAuth2TokenHandler(t))
		ts := httptest.NewServer(logMiddleware(t, mux))
		defer ts.Close()

		config.Set(configuration.API_URL, ts.URL)
		config.Set(configuration.WEB_APP_URL, ts.URL)

		authenticator := auth.NewOAuth2AuthenticatorWithOpts(
			config,
			auth.WithOpenBrowserFunc(headlessOpenBrowserFunc(t)),
		)

		err = entryPointDI(config, &logger, engine, authenticator)

		assert.NoError(t, err)
		assert.Equal(t, "{\"access_token\":\"a\",\"token_type\":\"b\",\"expiry\":\"0001-01-01T00:00:00Z\"}", config.GetString(auth.CONFIG_KEY_OAUTH_TOKEN))
	})

	t.Run("supports redirect to valid instance", func(t *testing.T) {
		config := configuration.NewInMemory()
		config.Set(authTypeParameter, nil)

		// Create mock server for successful oauth2 flow
		mux := http.NewServeMux()
		mux.HandleFunc("/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) {
			// Redirect to the redirect_uri with a mock authorization code
			redirectURI := r.URL.Query().Get("redirect_uri")
			state := r.URL.Query().Get("state")
			http.Redirect(w, r, redirectURI+"?code=mock-auth-code&state="+state+"&instance=api.region.snyk.io", http.StatusFound)
		})
		ts := httptest.NewServer(logMiddleware(t, mux))
		defer ts.Close()

		config.Set(configuration.WEB_APP_URL, ts.URL)
		c := &http.Client{}
		authenticator := auth.NewOAuth2AuthenticatorWithOpts(
			config,
			auth.WithHttpClient(c),
			auth.WithLogger(&logger),
			auth.WithOpenBrowserFunc(headlessOpenBrowserFunc(t)),
		)

		defer gock.OffAll()

		// Second instance
		gock.New("https://api.region.snyk.io").
			Post("/oauth2/token").
			Reply(200).
			JSON(map[string]string{
				"access_token":  "abc",
				"token_type":    "bearer",
				"refresh_token": "123",
				"expiry":        "3600",
			})

		// Pass through to our local oauth2 server
		gock.New("http://127.0.0.1").
			Persist().
			EnableNetworking()

		err = entryPointDI(config, &logger, engine, authenticator)

		assert.NoError(t, err)
		fmt.Println(logContent)
		assert.Equal(t, false, gock.HasUnmatchedRequest())
	})

	t.Run("fails with malformed state", func(t *testing.T) {
		config := configuration.NewInMemory()
		config.Set(authTypeParameter, nil)

		// Create mock server for unsuccessful oauth2 flow
		mux := http.NewServeMux()
		mux.HandleFunc("/oauth2/authorize", func(w http.ResponseWriter, r *http.Request) {
			// Redirect to the redirect_uri with a mock authorization code
			redirectURI := r.URL.Query().Get("redirect_uri")
			state := "invalid-state-object"
			http.Redirect(w, r, redirectURI+"?code=mock-auth-code&state="+state, http.StatusFound)
		})
		mux.HandleFunc("/oauth2/token", mockOAuth2TokenHandler(t))
		ts := httptest.NewServer(logMiddleware(t, mux))
		defer ts.Close()

		config.Set(configuration.API_URL, ts.URL)
		config.Set(configuration.WEB_APP_URL, ts.URL)

		authenticator := auth.NewOAuth2AuthenticatorWithOpts(
			config,
			auth.WithOpenBrowserFunc(headlessOpenBrowserFunc(t)),
		)
		err = entryPointDI(config, &logger, engine, authenticator)
		assert.ErrorContains(t, err, "incorrect response state")
	})
}

func mockOAuth2TokenHandler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		newToken := &oauth2.Token{
			AccessToken: "a",
			TokenType:   "b",
			Expiry:      time.Now().Add(60 * time.Second).UTC(),
		}
		data, err := json.Marshal(newToken)
		assert.Nil(t, err)

		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		_, err = w.Write(data)
		assert.Nil(t, err)
	}
}

func Test_auth_token(t *testing.T) {
	mockCtl := gomock.NewController(t)
	logContent := &bytes.Buffer{}
	config := configuration.NewInMemory()
	logger := zerolog.New(logContent)
	engine := mocks.NewMockEngine(mockCtl)
	authenticator := mocks.NewMockAuthenticator(mockCtl)

	engine.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Times(1)
	engine.EXPECT().Init().Times(1)

	err := InitAuth(engine)
	assert.NoError(t, err)

	err = engine.Init()
	assert.NoError(t, err)

	t.Run("happy", func(t *testing.T) {
		config.Set(authTypeParameter, authTypeToken)
		engine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any())
		err = entryPointDI(config, &logger, engine, authenticator)
		assert.NoError(t, err)
	})

	t.Run("automatically switch to token when API token is given", func(t *testing.T) {
		config.Set(authTypeParameter, nil)
		config.Set(ConfigurationNewAuthenticationToken, "00000000-0000-0000-0000-000000000000")
		engine.EXPECT().InvokeWithConfig(gomock.Any(), gomock.Any())
		err = entryPointDI(config, &logger, engine, authenticator)
		assert.NoError(t, err)
	})
}

func Test_autodetectAuth(t *testing.T) {
	t.Run("in stable versions, token by default", func(t *testing.T) {
		expected := authTypeOAuth
		config := configuration.NewInMemory()
		config.Set(configuration.PREVIEW_FEATURES_ENABLED, false)
		actual := autoDetectAuthType(config)
		assert.Equal(t, expected, actual)
	})

	t.Run("token for IDEs", func(t *testing.T) {
		expected := authTypeToken
		config := configuration.NewInMemory()
		config.Set(configuration.INTEGRATION_NAME, "VS_CODE")
		actual := autoDetectAuthType(config)
		assert.Equal(t, expected, actual)
	})

	t.Run("token for given API token", func(t *testing.T) {
		expected := authTypeToken
		config := configuration.NewInMemory()
		config.Set(ConfigurationNewAuthenticationToken, "00000000-0000-0000-0000-000000000000")
		actual := autoDetectAuthType(config)
		assert.Equal(t, expected, actual)
	})
}
