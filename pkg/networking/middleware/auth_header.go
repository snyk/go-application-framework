package middleware

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

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

func ShouldRequireAuthentication(
	apiUrl string,
	url *url.URL,
	additionalSubdomains []string,
	additionalUrls []string,
) (matchesPattern bool, err error) {
	subdomainsToCheck := append([]string{""}, additionalSubdomains...)
	for _, subdomain := range subdomainsToCheck {
		var matchesPattern bool
		var prefixUrl, referenceUrl string
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

	// if the default check for an api didn't succeed, check additional Urls if available
	requestUrl := url.String()
	for _, v := range additionalUrls {
		if strings.HasPrefix(requestUrl, v) {
			return true, nil
		}
	}

	return false, nil
}

// unauthErr is used to test for the unauthorized error code.
var unauthErr = snyk.NewUnauthorisedError("")

// IsAuthenticationErr returns whether the error represents an error
// catalog error indicating unauthorized.
func IsAuthenticationErr(err error) bool {
	for err != nil {
		if snykErr, ok := err.(snyk_errors.Error); ok {
			return unauthErr.ErrorCode == snykErr.ErrorCode
		}
		err = errors.Unwrap(err)
	}
	return false
}

// AddAuthenticationHeader determines whether a request needs authentication,
// negotiates authorization and sets request headers if necessary.
//
// If this fails due to an authentication error, the resulting error will match
// ErrAuthenticationFailed.
func AddAuthenticationHeader(
	authenticator auth.Authenticator,
	config configuration.Configuration,
	request *http.Request,
) error {
	apiUrl := config.GetString(configuration.API_URL)
	additionalSubdomains := config.GetStringSlice(configuration.AUTHENTICATION_SUBDOMAINS)
	additionalUrls := config.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS)
	isSnykApi, err := ShouldRequireAuthentication(apiUrl, request.URL, additionalSubdomains, additionalUrls)

	// requests to the api automatically get an authentication token attached
	if !isSnykApi {
		return err
	}

	err = authenticator.AddAuthenticationHeader(request)
	if err != nil {
		return snyk.NewUnauthorisedError("Authentication failed", snyk_errors.WithCause(err))
	}
	return nil
}
