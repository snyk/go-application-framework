package middleware

import (
	"net/http"
	"strings"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

type AuthHeaderMiddleware struct {
	next          http.RoundTripper
	authenticator auth.Authenticator
	config        configuration.Configuration
}

func NewAuthHeaderMiddleware(
	config configuration.Configuration,
	authenticator auth.Authenticator,
	roundTripper http.RoundTripper,
) *AuthHeaderMiddleware {
	return &AuthHeaderMiddleware{
		next:          roundTripper,
		config:        config,
		authenticator: authenticator,
	}
}

func (n *AuthHeaderMiddleware) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL == nil {
		return n.next.RoundTrip(request)
	}

	isSnykApi, err := n.IsSnykApi(request)

	// requests to the api automatically get an authentication token attached
	if err == nil && isSnykApi {
		err = n.authenticator.AddAuthenticationHeader(request)
		if err != nil {
			return nil, err
		}
	}

	return n.next.RoundTrip(request)
}

func (n *AuthHeaderMiddleware) IsSnykApi(request *http.Request) (bool, error) {
	// determine configured api url
	apiUrlString := n.config.GetString(configuration.API_URL)
	requestUrl, err := api.GetCanonicalApiUrl(request.URL.String())
	return strings.HasPrefix(requestUrl, apiUrlString), err
}
