package middleware

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

type UserAgentMiddleware struct {
	next               http.RoundTripper
	config             configuration.Configuration
	snykAppEnvironment *UserAgentInfo
}

func NewUserAgentMiddleware(
	config configuration.Configuration,
	roundTripper http.RoundTripper,
	snykAppEnvironment *UserAgentInfo,
) *UserAgentMiddleware {
	return &UserAgentMiddleware{
		next:               roundTripper,
		config:             config,
		snykAppEnvironment: snykAppEnvironment,
	}
}

func (n *UserAgentMiddleware) RoundTrip(request *http.Request) (*http.Response, error) {
	// Only add headers if the request is going to a Snyk API URL.
	apiUrl := n.config.GetString(configuration.API_URL)
	parsedUrl, err := url.Parse(apiUrl)
	if err != nil {
		return n.next.RoundTrip(request)
	}

	isSnykApi, err := IsSnykApi(apiUrl, request.URL, nil)
	if err != nil || n.snykAppEnvironment == nil || !isSnykUrl(parsedUrl.Hostname()) || !isSnykApi {
		return n.next.RoundTrip(request)
	}

	newRequest := request.Clone(request.Context())
	newRequest.Header.Add("User-Agent", n.snykAppEnvironment.ToUserAgentHeader())
	return n.next.RoundTrip(newRequest)
}

func isSnykUrl(hostname string) bool {
	return strings.HasSuffix(hostname, "snykgov.io") || strings.HasSuffix(hostname, "snyk.io")
}
