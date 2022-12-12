package networking

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-httpauth/pkg/httpauth"
	"github.com/stretchr/testify/assert"
)

func getConfig() configuration.Configuration {
	config := configuration.New()
	config.Set(configuration.API_URL, constants.SNYK_DEFAULT_API_URL)
	return config
}

func Test_GetDefaultHeader_WithAuth(t *testing.T) {
	config := getConfig()
	net := NewNetworkAccess(config)

	token := "1265457"
	config.Set(configuration.AUTHENTICATION_TOKEN, token)

	expectedHeader := http.Header{
		"User-Agent": {defaultUserAgent},
		// deepcode ignore HardcodedPassword/test: <please specify a reason of ignoring this>
		"Authorization": {"token " + token},
	}

	url, _ := url.Parse(config.GetString(configuration.API_URL))
	actualHeader := net.GetDefaultHeader(url)

	assert.Equal(t, expectedHeader, actualHeader)
}

func Test_GetDefaultHeader_WithoutAuth(t *testing.T) {
	config := getConfig()
	net := NewNetworkAccess(config)

	token := "1265457"
	config.Set(configuration.AUTHENTICATION_TOKEN, token)

	expectedHeader := http.Header{
		"User-Agent": {defaultUserAgent},
	}

	url, _ := url.Parse("https://www.myexample.com")
	actualHeader := net.GetDefaultHeader(url)

	assert.Equal(t, expectedHeader, actualHeader)
}

func Test_GetDefaultHeader_SkipHeaderForUrl(t *testing.T) {
	config := getConfig()
	net := NewNetworkAccess(config)

	token := "1265457"
	config.Set(configuration.AUTHENTICATION_TOKEN, token)
	net.AddHeaderField("Newfield", "newValue")

	expectedHeader := http.Header{
		"Newfield": {"newValue"},
	}

	expectedHeader2 := http.Header{
		HEADER_FIELD_AUTHORIZATION: {"token " + token},
		HEADER_FIELD_USER_AGENT:    {defaultUserAgent},
	}

	url, _ := url.Parse(config.GetString(configuration.API_URL))
	url2, _ := url.Parse(config.GetString(configuration.API_URL) + "?query=low")
	net.RemoveHeaderFieldForUrl(url, HEADER_FIELD_AUTHORIZATION)
	net.RemoveHeaderFieldForUrl(url, HEADER_FIELD_USER_AGENT)
	net.RemoveHeaderFieldForUrl(url, "SomethingNotExisting")
	net.RemoveHeaderFieldForUrl(url2, "Newfield")

	// invoke method under test
	actualHeader := net.GetDefaultHeader(url)
	assert.Equal(t, expectedHeader, actualHeader)

	// invoke method under test
	actualHeader2 := net.GetDefaultHeader(url2)
	assert.Equal(t, expectedHeader2, actualHeader2)
}

func Test_Roundtripper_SecureHTTPS(t *testing.T) {
	config := getConfig()
	net := NewNetworkAccess(config)

	roundtripper := net.GetRoundtripper()
	customRoundtripper := roundtripper.(*customRoundtripper)
	assert.NotNil(t, customRoundtripper)
	assert.False(t, customRoundtripper.encapsulatedRoundtripper.TLSClientConfig.InsecureSkipVerify)
}

func Test_Roundtripper_InsecureHTTPS(t *testing.T) {
	config := getConfig()
	net := NewNetworkAccess(config)

	config.Set(configuration.INSECURE_HTTPS, true)

	roundtripper := net.GetRoundtripper()
	customRoundtripper := roundtripper.(*customRoundtripper)
	assert.NotNil(t, customRoundtripper)
	assert.True(t, customRoundtripper.encapsulatedRoundtripper.TLSClientConfig.InsecureSkipVerify)
}

func Test_Roundtripper_ProxyAuth(t *testing.T) {
	config := getConfig()
	net := NewNetworkAccess(config)

	// case: enable AnyAuth
	config.Set(configuration.PROXY_AUTHENTICATION_MECHANISM, httpauth.StringFromAuthenticationMechanism(httpauth.AnyAuth))

	// invoke method under test
	roundtripper := net.GetRoundtripper()

	// find proxyAuthenticator used for AnyAuth
	ctRoundTripper := roundtripper.(*customRoundtripper)
	assert.NotNil(t, ctRoundTripper)
	assert.NotNil(t, ctRoundTripper.proxyAuthenticator)
	assert.Nil(t, ctRoundTripper.encapsulatedRoundtripper.Proxy)

	// case: disable Auth
	config.Set(configuration.PROXY_AUTHENTICATION_MECHANISM, httpauth.StringFromAuthenticationMechanism(httpauth.NoAuth))

	// invoke method under test
	roundtripper = net.GetRoundtripper()

	// with Auth disabled, no proxyAuthenticator should be available
	ctRoundTripper = roundtripper.(*customRoundtripper)
	assert.NotNil(t, ctRoundTripper)
	assert.Nil(t, ctRoundTripper.proxyAuthenticator)
	assert.NotNil(t, ctRoundTripper.encapsulatedRoundtripper.Proxy)
}

func Test_GetHTTPClient(t *testing.T) {
	config := getConfig()
	net := NewNetworkAccess(config)

	client := net.GetHttpClient()
	response, err := client.Get("https://www.snyk.io")
	assert.Nil(t, err)
	assert.Equal(t, 200, response.StatusCode)
}
