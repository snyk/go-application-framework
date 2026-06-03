package middleware

import (
	"io"
	"net/http"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

type NoAuthInterceptMiddleware struct {
	next   http.RoundTripper
	config configuration.Configuration
	logger *zerolog.Logger
}

func NewNoAuthInterceptMiddleware(
	config configuration.Configuration,
	logger *zerolog.Logger,
	next http.RoundTripper,
) *NoAuthInterceptMiddleware {
	return &NoAuthInterceptMiddleware{
		next:   next,
		config: config,
		logger: logger,
	}
}

func (m *NoAuthInterceptMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	if !m.config.GetBool(configuration.STOP_REQUESTS_WITHOUT_AUTH) {
		return m.next.RoundTrip(req)
	}

	if req.URL == nil {
		return m.next.RoundTrip(req)
	}

	apiUrl := m.config.GetString(configuration.API_URL)
	additionalSubdomains := m.config.GetStringSlice(configuration.AUTHENTICATION_SUBDOMAINS)
	additionalUrls := m.config.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS)

	requiresAuth, err := ShouldRequireAuthentication(apiUrl, req.URL, additionalSubdomains, additionalUrls)
	if err != nil || !requiresAuth {
		return m.next.RoundTrip(req)
	}

	if req.Header.Get("Authorization") == "" {
		m.logger.Debug().Str("url", req.URL.String()).Msg("request requires auth but no token present, blocking with 401")
		return &http.Response{
			StatusCode: http.StatusUnauthorized,
			Status:     "401 Unauthorized",
			Header:     make(http.Header),
			Body:       io.NopCloser(http.NoBody),
			Request:    req,
		}, nil
	}

	return m.next.RoundTrip(req)
}
