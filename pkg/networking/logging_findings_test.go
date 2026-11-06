package networking_test

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/logging"
	"github.com/snyk/go-application-framework/pkg/networking"
)

func Test_LogRequest_ShortenedRefreshRequestDoesNotLogTheEndOfTheRefreshToken(t *testing.T) {
	const refreshToken = "rt-0123456789abcdefghijklmnopqrstuvwxyz"
	config := configuration.NewInMemory()
	config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, `{"access_token":"at-0123456789","refresh_token":"`+refreshToken+`"}`)
	var output bytes.Buffer
	logger := zerolog.New(logging.NewScrubbingWriter(zerolog.MultiLevelWriter(&output), logging.GetScrubDictFromConfig(config))).Level(zerolog.TraceLevel)
	body := url.Values{"client_id": {"cli"}, "grant_type": {"refresh_token"}, "refresh_token": {refreshToken}}.Encode()
	request, err := http.NewRequest(http.MethodPost, "https://api.snyk.io/oauth2/token", strings.NewReader(body))
	require.NoError(t, err)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	networking.LogRequest(request, &logger)

	assert.Contains(t, output.String(), "body:")
	assert.NotContains(t, output.String(), refreshToken[len(refreshToken)-20:])
}
