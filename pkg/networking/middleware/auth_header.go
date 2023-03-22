package middleware

import (
	"net/http"
	"net/url"
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

	err := AddAuthenticationHeader(n.authenticator, n.config, request)
	if err != nil {
		return nil, err
	}

	return n.next.RoundTrip(request)
}

func ShouldRequireAuthentication(apiUrl string, url *url.URL) (bool, error) {
	requestUrl, err := api.GetCanonicalApiUrl(*url)
	if err != nil {
		return false, err
	}

	result := strings.HasPrefix(requestUrl, apiUrl)
	return result, nil
}

func AddAuthenticationHeader(authenticator auth.Authenticator, config configuration.Configuration, request *http.Request) error {
	apiUrl := config.GetString(configuration.API_URL)
	isSnykApi, err := ShouldRequireAuthentication(apiUrl, request.URL)

	// requests to the api automatically get an authentication token attached
	if !isSnykApi {
		return err
	}

	err = authenticator.AddAuthenticationHeader(request)
	return err
}
