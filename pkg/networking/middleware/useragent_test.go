package middleware

import (
	"net/http"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
)

func Test_RequestToSnykUrl_UserAgentAdded(t *testing.T) {
	config := configuration.NewInMemory()
	config.Set(configuration.API_URL, "https://api.snyk.io")
	capturer := &HeaderCaptureMiddleware{}
	userAgent := UserAgentFromConfig(config, "test-app", "0.0.1")
	mw := NewUserAgentMiddleware(config, capturer, &userAgent)

	req, err := http.NewRequest("GET", "https://api.snyk.io", nil)
	assert.NoError(t, err)
	_, err = mw.RoundTrip(req)
	assert.NoError(t, err)

	assert.Equal(t, userAgent.ToUserAgentHeader(), capturer.CapturedHeaders["User-Agent"])
}
