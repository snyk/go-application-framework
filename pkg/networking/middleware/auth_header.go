package middleware

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/internal/machinecredential"
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
	var machineErr *machinecredential.AuthenticationError
	if requiresAuth && errors.As(err, &machineErr) {
		if n.logger != nil {
			n.logger.Debug().Err(err).Str("url", newRequest.URL.String()).Msg("machine authentication failed, blocking the request")
		}
		// Not nil: given a nil response, the CLI's legacy proxy relays the original request itself.
		return unauthorizedResponse(newRequest), err
	}
	if err != nil {
		if n.logger != nil {
			n.logger.Debug().Err(err).Str("url", newRequest.URL.String()).Msg("could not determine if request requires auth, allowing through")
		}
		return n.next.RoundTrip(newRequest)
	}

	// The 401 gate fires only for token/PAT auth (no token → no Authorization header set).
	// For OAuth, an expired/unrefreshable token causes addAuthenticationHeader to return an error,
	// which is handled above (log + passthrough) — the Authorization check below is never reached.
	if n.config.GetBool(configuration.STOP_REQUESTS_WITHOUT_AUTH) && requiresAuth && newRequest.Header.Get("Authorization") == "" {
		if n.logger != nil {
			n.logger.Debug().Str("url", newRequest.URL.String()).Msg("request requires auth but no token present, blocking with 401")
		}
		return unauthorizedResponse(newRequest), errFromStatusCode(http.StatusUnauthorized)
	}

	return n.next.RoundTrip(newRequest)
}

func unauthorizedResponse(request *http.Request) *http.Response {
	return &http.Response{
		StatusCode: http.StatusUnauthorized,
		Status:     "401 Unauthorized",
		Header:     make(http.Header),
		Body:       io.NopCloser(http.NoBody),
		Request:    request,
	}
}

func ShouldRequireAuthentication(
	apiUrl string,
	requestUrl *url.URL,
	additionalSubdomains []string,
	additionalUrls []string,
) (matchesPattern bool, err error) {
	if apiUrl == "" {
		apiUrl = constants.SNYK_DEFAULT_API_URL
	}
	apiBase, err := url.Parse(apiUrl)
	if err != nil {
		return false, err
	}

	canonicalUrl, err := api.GetCanonicalApiAsUrl(*requestUrl)
	if err != nil {
		return false, err
	}
	if isWithinUrl(&canonicalUrl, apiBase) {
		return true, nil
	}

	for _, subdomain := range additionalSubdomains {
		subdomainUrl, err := api.DeriveSubdomainUrl(apiUrl, subdomain)
		if err != nil {
			return false, err
		}
		base, err := url.Parse(subdomainUrl)
		if err != nil {
			return false, err
		}
		if isWithinUrl(requestUrl, base) {
			return true, nil
		}
	}

	// if the default check for an api didn't succeed, check additional Urls if available
	for _, additionalUrl := range additionalUrls {
		base, err := url.Parse(additionalUrl)
		if err != nil {
			// An entry that is not a URL can never match a request.
			continue
		}
		if isWithinUrl(requestUrl, base) {
			return true, nil
		}
	}

	return false, nil
}

func isWithinUrl(u, base *url.URL) bool {
	return api.MatchesOrigin(u, base) && api.HasPathPrefix(u, base)
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
