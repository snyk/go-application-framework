package middleware

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

type AuthHeaderMiddleware struct {
	next          http.RoundTripper
	authenticator auth.Authenticator
	config        configuration.Configuration
	logger        *zerolog.Logger
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

func NewAuthHeaderMiddlewareWithLogger(
	config configuration.Configuration,
	authenticator auth.Authenticator,
	roundTripper http.RoundTripper,
	logger *zerolog.Logger,
) *AuthHeaderMiddleware {
	m := NewAuthHeaderMiddleware(config, authenticator, roundTripper)
	m.logger = logger
	return m
}

func (n *AuthHeaderMiddleware) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL == nil {
		return n.next.RoundTrip(request)
	}

	// RoundTrippers should not modify the source request according to the docs, so cloning is used.
	newRequest := request.Clone(request.Context())
	requiresAuth, err := addAuthenticationHeader(n.authenticator, n.config, newRequest)
	if err != nil {
		return nil, err
	}

	if n.config.GetBool(configuration.STOP_REQUESTS_WITHOUT_AUTH) && requiresAuth && newRequest.Header.Get("Authorization") == "" {
		if n.logger != nil {
			n.logger.Debug().Str("url", newRequest.URL.String()).Msg("request requires auth but no token present, blocking with 401")
		}
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Status:     "401 Unauthorized",
			Header:     make(http.Header),
			Body:       io.NopCloser(http.NoBody),
			Request:    newRequest,
		}, nil
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

// ErrAuthenticationFailed indicates that authentication failed in the
// networking middleware.
var ErrAuthenticationFailed = fmt.Errorf("authentication failed")

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
	_, err := addAuthenticationHeader(authenticator, config, request)
	return err
}

// addAuthenticationHeader is the internal version that also returns whether
// the URL required auth. Used by RoundTrip to drive the no-auth intercept
// without a second URL match.
func addAuthenticationHeader(
	authenticator auth.Authenticator,
	config configuration.Configuration,
	request *http.Request,
) (requiresAuth bool, err error) {
	apiUrl := config.GetString(configuration.API_URL)
	additionalSubdomains := config.GetStringSlice(configuration.AUTHENTICATION_SUBDOMAINS)
	additionalUrls := config.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS)
	requiresAuth, err = ShouldRequireAuthentication(apiUrl, request.URL, additionalSubdomains, additionalUrls)

	if !requiresAuth {
		return false, err
	}

	err = authenticator.AddAuthenticationHeader(request)
	if err != nil {
		return true, errors.Join(err, ErrAuthenticationFailed)
	}
	return true, nil
}
