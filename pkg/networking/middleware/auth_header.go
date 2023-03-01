package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
)

type AuthHeaderMiddleware struct {
	next          http.RoundTripper
	authenticator networking.Authenticator
	config        configuration.Configuration
}

func NewAuthHeaderMiddleware(
	config configuration.Configuration,
	authenticator networking.Authenticator,
	roundTripper http.RoundTripper,
) *AuthHeaderMiddleware {
	return &AuthHeaderMiddleware{
		next:          roundTripper,
		config:        config,
		authenticator: authenticator,
	}
}

func (n *AuthHeaderMiddleware) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL != nil {
		// determine configured api url
		apiUrlString := n.config.GetString(configuration.API_URL)
		apiUrl, err := url.Parse(apiUrlString)
		if err != nil {
			apiUrl, _ = url.Parse(constants.SNYK_DEFAULT_API_URL)
		}

		// requests to the api automatically get an authentication token attached
		if strings.Contains(request.URL.Host, apiUrl.Host) {
			err = n.authenticator.Authorize(request)
			if err != nil {
				return nil, err
			}
		}
	}

	return n.next.RoundTrip(request)
}
