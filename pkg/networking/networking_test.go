package networking

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking/certs"
	"github.com/snyk/go-httpauth/pkg/httpauth"
	"github.com/stretchr/testify/assert"
)

func getConfig() configuration.Configuration {
	config := configuration.New()
	config.Set(configuration.API_URL, constants.SNYK_DEFAULT_API_URL)
	config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, "")
	config.Set(configuration.AUTHENTICATION_TOKEN, "")
	return config
}

func Test_HttpClient_CallingApiUrl_UsesAuthHeaders(t *testing.T) {
	config := getConfig()
	net := NewNetworkAccess(config)
	client := net.GetHttpClient()
	token := "1265457"
	config.Set(configuration.AUTHENTICATION_TOKEN, token)
	expectedHeader := http.Header{
		"User-Agent": {defaultUserAgent},
		// deepcode ignore HardcodedPassword/test: <please specify a reason of ignoring this>
		"Authorization": {"token " + token},
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

func Test_GetDefaultHeader_WithoutAuth(t *testing.T) {
	config := getConfig()
	net := NewNetworkAccess(config)

	token := "1265457"
	config.Set(configuration.AUTHENTICATION_TOKEN, token)

	expectedHeader := http.Header{
		"User-Agent": {defaultUserAgent},
	}

	// run method under test multiple times to ensure that it behaves the same way each time
	for i := 0; i < 3; i++ {
		url, _ := url.Parse("https://www.myexample.com")
		actualHeader := net.GetDefaultHeader(url)
		assert.Equal(t, expectedHeader, actualHeader)
	}
}

func Test_Roundtripper_SecureHTTPS(t *testing.T) {
	config := getConfig()
	net := NewNetworkAccess(config).(*NetworkImpl)

	roundtripper := net.GetRoundTripper()
	transport := net.configureRoundTripper(http.DefaultTransport.(*http.Transport))
	customRoundtripper := roundtripper.(*customRoundtripper)
	assert.NotNil(t, customRoundtripper)
	assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func Test_Roundtripper_InsecureHTTPS(t *testing.T) {
	config := getConfig()
	net := NewNetworkAccess(config).(*NetworkImpl)

	config.Set(configuration.INSECURE_HTTPS, true)

	roundtripper := net.GetRoundTripper()
	transport := net.configureRoundTripper(http.DefaultTransport.(*http.Transport))
	customRoundtripper := roundtripper.(*customRoundtripper)
	assert.NotNil(t, customRoundtripper)
	assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
}

func Test_Roundtripper_ProxyAuth(t *testing.T) {
	config := getConfig()
	net := NewNetworkAccess(config).(*NetworkImpl)

	// case: enable AnyAuth
	config.Set(configuration.PROXY_AUTHENTICATION_MECHANISM, httpauth.StringFromAuthenticationMechanism(httpauth.AnyAuth))

	// invoke method under test
	roundtripper := net.GetRoundTripper()
	transport := net.configureRoundTripper(http.DefaultTransport.(*http.Transport))

	// find proxyAuthenticator used for AnyAuth
	ctRoundTripper := roundtripper.(*customRoundtripper)
	assert.NotNil(t, ctRoundTripper)
	assert.NotNil(t, transport.DialContext)
	assert.Nil(t, transport.Proxy)

	// case: disable Auth
	config.Set(configuration.PROXY_AUTHENTICATION_MECHANISM, httpauth.StringFromAuthenticationMechanism(httpauth.NoAuth))

	// invoke method under test
	roundtripper = net.GetRoundTripper()
	transport = net.configureRoundTripper(http.DefaultTransport.(*http.Transport))

	// with Auth disabled, no proxyAuthenticator should be available
	ctRoundTripper = roundtripper.(*customRoundtripper)
	assert.NotNil(t, ctRoundTripper)
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
	net := NewNetworkAccess(config)

	certPem, _keyPem, _ := certs.MakeSelfSignedCert("mycert", []string{"localhost"}, log.Default())
	certFile, _ := os.CreateTemp("", "")
	certFile.Write([]byte(certPem))

	keyFile, _ := os.CreateTemp("", "")
	keyFile.Write([]byte(_keyPem))

	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "Hello, TLS!\n")
		fmt.Println("hello")
	})

	listen := func() {
		err := http.ListenAndServeTLS(":8443", certFile.Name(), keyFile.Name(), nil)
		assert.Nil(t, err)
	}
	go listen()

	time.Sleep(1000)

	// test that we can't connect without adding the ca certificates
	client := net.GetHttpClient()
	_, err := client.Get("https://localhost:8443/")
	assert.NotNil(t, err)

	// invoke method under test
	err = net.AddRootCAs(certFile.Name())
	assert.Nil(t, err)

	// test connectability after adding ca certificates
	client = net.GetHttpClient()
	_, err = client.Get("https://localhost:8443/")
	assert.Nil(t, err)
}
