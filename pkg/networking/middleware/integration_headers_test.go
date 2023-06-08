package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
)

func Test_IntegrationInConfig_IntegrationAddedToRoundTripper(t *testing.T) {
	const integrationName = "my-special-integration"
	const integrationVersion = "0.0.1rc1-preview1-pre-alpha-preview"
	t.Parallel()
	expectedIntegrationHeader := integrationName + "/" + integrationVersion

	config := configuration.New()
	config.Set(configuration.INTEGRATION_NAME, integrationName)
	config.Set(configuration.INTEGRATION_VERSION, integrationVersion)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(r.Header.Get("x-snyk-integration")))
		assert.NoError(t, err)
	})
	mockServer := httptest.NewServer(handler)
	config.Set(configuration.API_URL, mockServer.URL)
	t.Cleanup(mockServer.Close)
	rt := NewIntegrationHeaderMiddleware(config, http.DefaultTransport)
	client := &http.Client{Transport: rt}

	// Act
	rsp, err := client.Get(mockServer.URL)
	t.Cleanup(func() { _ = rsp.Body.Close() })
	assert.NoError(t, err)

	// Assert
	body, err := io.ReadAll(rsp.Body)
	assert.NoError(t, err)
	assert.Equal(t, expectedIntegrationHeader, string(body))
}

func Test_RequestNotToSnykApi_IntegrationNotAddedToRoundTripper(t *testing.T) {
	const integrationName = "my-special-integration"
	const integrationVersion = "0.0.1rc1-preview1-pre-alpha-preview"
	t.Parallel()

	config := configuration.New()
	config.Set(configuration.INTEGRATION_NAME, integrationName)
	config.Set(configuration.INTEGRATION_VERSION, integrationVersion)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(r.Header.Get("x-snyk-integration")))
		assert.NoError(t, err)
	})
	mockServer := httptest.NewServer(handler)
	config.Set(configuration.API_URL, "https://app.au.eu.cn.il.swe.snyk.io")
	t.Cleanup(mockServer.Close)
	rt := NewIntegrationHeaderMiddleware(config, http.DefaultTransport)
	client := &http.Client{Transport: rt}

	// Act
	rsp, err := client.Get(mockServer.URL)
	t.Cleanup(func() { _ = rsp.Body.Close() })
	assert.NoError(t, err)

	// Assert
	body, err := io.ReadAll(rsp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "", string(body))
}

func Test_NoIntegrationInConfig_IntegrationNotAddedToRoundTripper(t *testing.T) {
	t.Parallel()
	config := configuration.New()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(r.Header.Get("x-snyk-integration")))
		assert.NoError(t, err)
	})
	mockServer := httptest.NewServer(handler)
	t.Cleanup(mockServer.Close)
	rt := NewIntegrationHeaderMiddleware(config, http.DefaultTransport)
	client := &http.Client{Transport: rt}

	// Act
	rsp, err := client.Get(mockServer.URL)
	t.Cleanup(func() { _ = rsp.Body.Close() })
	assert.NoError(t, err)

	// Assert
	body, err := io.ReadAll(rsp.Body)
	assert.NoError(t, err)
	assert.Equal(t, "", string(body))
}
