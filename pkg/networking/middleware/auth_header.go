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

	// RoundTrippers should not modify the source request according to the docs, so cloning is used.
	newRequest := request.Clone(request.Context())
	err := AddAuthenticationHeader(n.authenticator, n.config, newRequest)
	if err != nil {
		return nil, err
	}

	return n.next.RoundTrip(newRequest)
}

// IsSnykApi checks if a URL aligns with a pattern of specified Snyk API URLs.
//
// apiUrl: Base API URL.
// url: The URL to check.
// additionalSubdomains: Subdomains to append to apiUrl for comparison.
//
// Returns true if the URL matches the pattern, false otherwise.
// In case of an error generating the URL, an error is returned.
//
// Example 1:
// apiUrl: "https://snyk.io/api/"
// url: "https://snyk.io/api/v1/projects"
// additionalSubdomains: []string{}
// Result: true, nil // The URL matches the base API URL
//
// Example 2:
// apiUrl: "https://snyk.io/api/"
// url: "https://test.snyk.io/api/v1/projects"
// additionalSubdomains: []string{"test"}
// Result: true, nil // The URL matches the API URL with the "test" subdomain
func IsSnykApi(apiUrl string, url *url.URL, additionalSubdomains []string) (matchesPattern bool, err error) {
	subdomainsToCheck := append([]string{""}, additionalSubdomains...)
	for _, subdomain := range subdomainsToCheck {
		matchesPattern := false
		referenceUrl := ""
		prefixUrl := ""
		if len(subdomain) == 0 {
			prefixUrl = apiUrl
			referenceUrl, err = api.GetCanonicalApiUrl(*url)
		} else {
			referenceUrl = url.String()
			prefixUrl, err = api.DeriveSubdomainUrl(apiUrl, subdomain)
		}

		if err != nil {
			return false, err
		}

		matchesPattern = strings.HasPrefix(referenceUrl, prefixUrl)
		if matchesPattern {
			return matchesPattern, nil
		}
	}

	return false, nil

}

func AddAuthenticationHeader(
	authenticator auth.Authenticator,
	config configuration.Configuration,
	request *http.Request,
) error {
	apiUrl := config.GetString(configuration.API_URL)
	additionalSubdomains := config.GetStringSlice(configuration.AUTHENTICATION_SUBDOMAINS)
	isSnykApi, err := IsSnykApi(apiUrl, request.URL, additionalSubdomains)

	// requests to the api automatically get an authentication token attached
	if !isSnykApi {
		return err
	}

	err = authenticator.AddAuthenticationHeader(request)
	return err
}
