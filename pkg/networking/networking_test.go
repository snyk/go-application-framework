package networking

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/go-httpauth/pkg/httpauth"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking/certs"
)

func getConfig() configuration.Configuration {
	config := configuration.NewWithOpts(configuration.WithSupportedEnvVarPrefixes("snyk_"))
	config.Set(configuration.API_URL, constants.SNYK_DEFAULT_API_URL)
	config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, "")
	config.Set(configuration.AUTHENTICATION_TOKEN, "")
	config.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)
	return config
}

func Test_HttpClient_CallingApiUrl_Unauthorized(t *testing.T) {
	config := getConfig()
	net := NewNetworkAccess(config)
	client := net.GetUnauthorizedHttpClient()
	token := "1265457"
	userAgent := "James Bond"
	config.Set(configuration.AUTHENTICATION_TOKEN, token)
	net.AddHeaderField("User-Agent", userAgent)
	expectedHeader := http.Header{
		"User-Agent": {userAgent},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key, expectedValue := range expectedHeader {
			assert.Equal(t, expectedValue, r.Header[key])
		}
	})
	server := httptest.NewServer(handler)
	config.Set(configuration.API_URL, server.URL)
	_, err := client.Get(server.URL)
	assert.NoError(t, err)
}

func Test_HttpClient_CallingApiUrl_UsesAuthHeaders(t *testing.T) {
	config := getConfig()
	net := NewNetworkAccess(config)
	client := net.GetHttpClient()
	token := "1265457"
	userAgent := "James Bond"
	config.Set(configuration.AUTHENTICATION_TOKEN, token)
	net.AddHeaderField("User-Agent", userAgent)
	expectedHeader := http.Header{
		"User-Agent":    {userAgent},
		"Authorization": {"token " + token},
		"Session-Token": {"token " + token},
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key, expectedValue := range expectedHeader {
			assert.Equal(t, expectedValue, r.Header[key])
		}
	})
	server := httptest.NewServer(handler)
	config.Set(configuration.API_URL, server.URL)
	_, err := client.Get(server.URL)
	assert.NoError(t, err)
}

func Test_HttpClient_CallingApiUrl_UsesAuthHeaders_OAuth(t *testing.T) {
	config := getConfig()
	accessToken := "access me"
	integrationName := "my-integration"
	integrationVersion := "1.0.0"

	expectedToken := &oauth2.Token{
		AccessToken:  accessToken,
		TokenType:    "b",
		RefreshToken: "c",
		Expiry:       time.Now().Add(time.Minute * 20),
	}

	expectedTokenString, err := json.Marshal(expectedToken)
	assert.NoError(t, err)

	expectedHeaders := map[string]string{
		// deepcode ignore HardcodedPassword/test: <please specify a reason of ignoring this>
		"Authorization": "Bearer " + accessToken,
		"Session-Token": "Bearer " + accessToken,
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for key, expectedValue := range expectedHeaders {
			assert.Equal(t, expectedValue, r.Header.Get(key)) // Use Get for case-insensitive comparison
		}
	})
	config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, string(expectedTokenString))
	config.Set(configuration.INTEGRATION_NAME, integrationName)
	config.Set(configuration.INTEGRATION_VERSION, integrationVersion)
	server := httptest.NewServer(handler)
	config.Set(configuration.API_URL, server.URL)
	net := NewNetworkAccess(config)
	client := net.GetHttpClient()

	_, err = client.Get(server.URL)
	assert.NoError(t, err)
}

func Test_HttpClient_CallingNonApiUrl(t *testing.T) {
	config := getConfig()
	net := NewNetworkAccess(config)
	client := net.GetHttpClient()
	token := "1265457"
	config.Set(configuration.AUTHENTICATION_TOKEN, token)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers := make(map[string]string)
		for key := range r.Header {
			headers[key] = r.Header.Get(key)
		}
		headersJson, err := json.Marshal(headers)
		assert.NoError(t, err)
		_, err = w.Write(headersJson)
		assert.NoError(t, err)
	})
	server := httptest.NewServer(handler)
	config.Set(configuration.API_URL, "https://www.example.com/not/the/server/URL")
	rsp, err := client.Get(server.URL)
	assert.NoError(t, err)
	capturedHeaders := make(map[string]string)
	rspBody, err := io.ReadAll(rsp.Body)
	assert.NoError(t, err)
	assert.NoError(t, json.Unmarshal(rspBody, &capturedHeaders))

	t.Run("No auth headers", func(t *testing.T) { assert.NotContains(t, capturedHeaders, "Authorization") })
	t.Run("No User-Agent", func(t *testing.T) {
		ua := capturedHeaders["User-Agent"]
		assert.NotEmpty(t, ua)
		assert.NotContains(t, ua, "snyk")
		assert.Contains(t, ua, "Go-http-client") // By default, this is the User-Agent in go HTTP client
	})
}

func Test_RoundTripper_SecureHTTPS(t *testing.T) {
	config := getConfig()
	net, ok := NewNetworkAccess(config).(*networkImpl)
	assert.True(t, ok)
	transport := net.configureRoundTripper(http.DefaultTransport.(*http.Transport)) //nolint:errcheck //in this test, the type is clear
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func Test_RoundTripper_InsecureHTTPS(t *testing.T) {
	config := getConfig()
	net, ok := NewNetworkAccess(config).(*networkImpl)
	assert.True(t, ok)

	config.Set(configuration.INSECURE_HTTPS, true)
	transport := net.configureRoundTripper(http.DefaultTransport.(*http.Transport)) //nolint:errcheck //in this test, the type is clear
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func Test_RoundTripper_ProxyAuth(t *testing.T) {
	config := getConfig()
	net, ok := NewNetworkAccess(config).(*networkImpl)
	assert.True(t, ok)

	// case: enable AnyAuth
	config.Set(configuration.PROXY_AUTHENTICATION_MECHANISM, httpauth.StringFromAuthenticationMechanism(httpauth.AnyAuth))

	// invoke method under test
	transport := net.configureRoundTripper(http.DefaultTransport.(*http.Transport)) //nolint:errcheck //in this test, the type is clear

	assert.NotNil(t, transport.DialContext)
	assert.Nil(t, transport.Proxy)

	// case: disable Auth
	config.Set(configuration.PROXY_AUTHENTICATION_MECHANISM, httpauth.StringFromAuthenticationMechanism(httpauth.NoAuth))

	// invoke method under test
	transport = net.configureRoundTripper(http.DefaultTransport.(*http.Transport)) //nolint:errcheck //in this test, the type is clear

	// with Auth disabled, no proxyAuthenticator should be available
	assert.Nil(t, transport.DialContext)
	assert.NotNil(t, transport.Proxy)
}

func Test_GetHTTPClient(t *testing.T) {
	config := getConfig()
	net := NewNetworkAccess(config)

	client := net.GetHttpClient()
	response, err := client.Get("https://www.snyk.io")
	assert.Nil(t, err)
	assert.Equal(t, 200, response.StatusCode)
}

func Test_GetHTTPClient_EmptyCAs(t *testing.T) {
	config := getConfig()
	config.Set(configuration.DEBUG, true)

	certPem, _keyPem, err := certs.MakeSelfSignedCert("mycert", []string{"localhost"}, log.Default())
	assert.NoError(t, err)
	certFile, err := os.CreateTemp("", "")
	assert.NoError(t, err)
	_, err = certFile.Write(certPem)
	assert.NoError(t, err)

	keyFile, err := os.CreateTemp("", "")
	assert.NoError(t, err)
	_, err = keyFile.Write(_keyPem)
	assert.NoError(t, err)

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		_, err = io.WriteString(w, "Hello, TLS!\n")
		assert.NoError(t, err)
		fmt.Println("hello")
	})

	listenerReady := make(chan struct{})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	t.Cleanup(func() {
		listener.Close()
	})

	serverURL := fmt.Sprintf("https://localhost:%d/", listener.Addr().(*net.TCPAddr).Port) //nolint:errcheck //in this test, the type is clear
	listen := func() {
		listenerReady <- struct{}{} // Signal that listener is ready (using empty struct)
		//nolint:gosec // client timeouts not a concern in tests
		serveErr := http.ServeTLS(listener, nil, certFile.Name(), keyFile.Name())
		t.Log("server stopped", serveErr)
	}
	go listen()

	<-listenerReady // Block until listener is ready

	// test that we can't connect without adding the ca certificates
	networkAccess := NewNetworkAccess(config)
	client := networkAccess.GetHttpClient()
	_, err = client.Get(serverURL)
	assert.NotNil(t, err)

	// invoke method under test
	config.Set(configuration.ADD_TRUSTED_CA_FILE, certFile.Name())
	networkAccess = NewNetworkAccess(config)

	// test connectability after adding ca certificates
	client = networkAccess.GetHttpClient()
	_, err = client.Get(serverURL)
	assert.Nil(t, err)
}

func Test_AddHeaders_AddsDefaultAndAuthHeaders(t *testing.T) {
	expectedHeader := http.Header{
		"Secret-Header": {"secret-value"},
		"Authorization": {"Bearer MyToken"},
		"Session-Token": {"Bearer MyToken"},
		"Request-Id":    {"my-request"},
	}

	replaceableHeader := "I was here first"

	config := getConfig()
	config.Set(configuration.AUTHENTICATION_BEARER_TOKEN, "MyToken")
	net := NewNetworkAccess(config)
	net.AddHeaderField("secret-header", "secret-value")
	net.AddDynamicHeaderField("request-id", func(values []string) []string {
		assert.Equal(t, []string{replaceableHeader}, values)
		return []string{"my-request"}
	})

	request, err := http.NewRequest(http.MethodGet, "https://api.snyk.io", nil)
	request.Header.Add("request-id", replaceableHeader)
	assert.NoError(t, err)
	err = net.AddHeaders(request)
	assert.NoError(t, err)

	assert.Equal(t, expectedHeader, request.Header)
}

func Test_AddUserAgent_AddsUserAgentHeaderToSnykApiRequests(t *testing.T) {
	app := "snyk-ls"
	appVersion := "20230508.144458"
	osName := "DARWIN"
	arch := "ARM64"
	integrationName := "VS_CODE"
	integrationVersion := "1.20.1"
	integrationEnvironment := "language-server"
	integrationEnvironmentVersion := "1.2.3.4"
	expectedHeader := fmt.Sprint(
		app, "/", appVersion,
		" (", osName, ";", arch, ") ",
		integrationName, "/", integrationVersion,
		" (", integrationEnvironment, "/", integrationEnvironmentVersion, ")",
	)

	config := getConfig()
	net := NewNetworkAccess(config)
	request, err := http.NewRequest(http.MethodGet, "https://api.snyk.io", nil)
	assert.Nil(t, err)
	userAgentInfo := UserAgentInfo{
		App:                           app,
		AppVersion:                    appVersion,
		Integration:                   integrationName,
		IntegrationVersion:            integrationVersion,
		IntegrationEnvironment:        integrationEnvironment,
		IntegrationEnvironmentVersion: integrationEnvironmentVersion,
		OS:                            osName,
		Arch:                          arch,
	}
	net.AddHeaderField("User-Agent", userAgentInfo.String())
	err = net.AddHeaders(request)
	assert.Nil(t, err)
	assert.Equal(t, expectedHeader, request.Header.Get("User-Agent"))
}

func Test_AddUserAgent_MissingIntegrationEnvironment_FormattedCorrectly(t *testing.T) {
	app := "snyk-ls"
	appVersion := "20230508.144458"
	osName := "DARWIN"
	arch := "ARM64"
	integrationName := "VS_CODE"
	integrationVersion := "1.20.1"
	expectedHeader := fmt.Sprint(
		app, "/", appVersion,
		" (", osName, ";", arch, ") ",
		integrationName, "/", integrationVersion,
	)

	config := getConfig()
	net := NewNetworkAccess(config)
	request, err := http.NewRequest(http.MethodGet, "https://api.snyk.io", nil)
	assert.Nil(t, err)

	userAgentInfo := UserAgentInfo{
		App:                app,
		AppVersion:         appVersion,
		Integration:        integrationName,
		IntegrationVersion: integrationVersion,
		OS:                 osName,
		Arch:               arch,
	}
	net.AddHeaderField("User-Agent", userAgentInfo.String())
	err = net.AddHeaders(request)
	assert.Nil(t, err)
	assert.Equal(t, expectedHeader, request.Header.Get("User-Agent"))
}

func Test_AddUserAgent_NoIntegrationInfo_FormattedCorrectly(t *testing.T) {
	app := "snyk-ls"
	appVersion := "20230508.144458"
	osName := "DARWIN"
	arch := "ARM64"
	expectedHeader := fmt.Sprint(
		app, "/", appVersion,
		" (", osName, ";", arch, ")",
	)

	config := getConfig()
	net := NewNetworkAccess(config)
	request, err := http.NewRequest(http.MethodGet, "https://api.snyk.io", nil)
	assert.Nil(t, err)
	t.Run("Without integration environment", func(t *testing.T) {
		userAgentInfo := UserAgentInfo{
			App:        app,
			AppVersion: appVersion,
			OS:         osName,
			Arch:       arch,
		}
		net.AddHeaderField("User-Agent", userAgentInfo.String())
		err = net.AddHeaders(request)
		assert.Nil(t, err)
		assert.Equal(t, expectedHeader, request.Header.Get("User-Agent"))
	})

	t.Run("With integration environment", func(t *testing.T) {
		userAgentInfo := UserAgentInfo{
			App:                           app,
			AppVersion:                    appVersion,
			OS:                            osName,
			Arch:                          arch,
			IntegrationEnvironment:        "Doesn't matter",
			IntegrationEnvironmentVersion: "Shouldn't show",
		}
		net.AddHeaderField("User-Agent", userAgentInfo.String())
		err = net.AddHeaders(request)
		assert.Nil(t, err)
		assert.Equal(t, expectedHeader, request.Header.Get("User-Agent"))
	})
}

func Test_UserAgentInfo_WithOSManuallySet(t *testing.T) {
	expectedOs := "myOs"
	ua := UserAgent(UaWithOS(expectedOs))
	assert.Equal(t, expectedOs, ua.OS)
}

func Test_UserAgentInfo_Complete(t *testing.T) {
	expectedOs := "myOs"
	expectedAppName := "myApp"
	expectedAppVersion := "12.23.5"
	expectedIntName := "Int"
	expectedIntVersion := "1.2.3"
	expectedIntEnvName := "IntEnv"
	expectedIntEnvVersion := "4.5.6"

	t.Setenv("SNYK_INTEGRATION_NAME", expectedIntName)
	t.Setenv("SNYK_INTEGRATION_VERSION", expectedIntVersion)
	t.Setenv("SNYK_INTEGRATION_ENVIRONMENT", expectedIntEnvName)
	t.Setenv("SNYK_INTEGRATION_ENVIRONMENT_VERSION", expectedIntEnvVersion)

	config := getConfig()

	ua := UserAgent(UaWithOS(expectedOs), UaWithConfig(config), UaWithApplication(expectedAppName, expectedAppVersion))

	t.Log(ua.String())

	assert.Equal(t, expectedOs, ua.OS)
	assert.Equal(t, expectedAppName, ua.App)
	assert.Equal(t, expectedAppVersion, ua.AppVersion)
	assert.Equal(t, expectedIntName, ua.Integration)
	assert.Equal(t, expectedIntVersion, ua.IntegrationVersion)
	assert.Equal(t, expectedIntEnvName, ua.IntegrationEnvironment)
	assert.Equal(t, expectedIntEnvVersion, ua.IntegrationEnvironmentVersion)
}

func TestNetworkImpl_Clone(t *testing.T) {
	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	network := NewNetworkAccess(config)

	config2 := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	config2.Set(configuration.AUTHENTICATION_TOKEN, "test")
	clonedNetwork := network.Clone()
	clonedNetwork.SetConfiguration(config2)

	url1, err := url.Parse("")
	assert.NoError(t, err)
	req1 := &http.Request{
		Header: http.Header{},
		URL:    url1,
	}
	req2 := &http.Request{
		Header: http.Header{},
		URL:    url1,
	}

	err = network.AddHeaders(req1)
	assert.NoError(t, err)
	err = clonedNetwork.AddHeaders(req2)
	assert.NoError(t, err)

	assert.NotEqual(t, req1, req2)
	assert.NotEqual(t, network.GetConfiguration(), clonedNetwork.GetConfiguration())
}

func TestNetworkImpl_ErrorHandler(t *testing.T) {
	expectedErr := snyk.NewUnauthorisedError("no auth")
	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	t.Run("returns the error from the handler", func(t *testing.T) {
		network := NewNetworkAccess(config)
		network.AddErrorHandler(func(err error, ctx context.Context) error {
			return expectedErr // overrides the previous error
		})
		client := network.GetHttpClient()
		_, err := client.Get(server.URL)
		assert.ErrorAs(t, err, &expectedErr)
	})

	t.Run("no error if the handler is not specified", func(t *testing.T) {
		network := NewNetworkAccess(config)
		network.AddErrorHandler(nil)
		client := network.GetHttpClient()
		res, err := client.Get(server.URL)
		assert.Nil(t, err)
		assert.Equal(t, res.StatusCode, http.StatusUnauthorized)
	})

	t.Run("unauthorized http client", func(t *testing.T) {
		network := NewNetworkAccess(config)
		network.AddErrorHandler(func(err error, ctx context.Context) error {
			return expectedErr // overrides the previous error
		})
		client := network.GetUnauthorizedHttpClient()
		_, err := client.Get(server.URL)
		assert.ErrorAs(t, err, &expectedErr)
	})
}
