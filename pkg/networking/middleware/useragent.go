package middleware

import (
	"net/http"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

type UserAgentMiddleware struct {
	next               http.RoundTripper
	config             configuration.Configuration
	snykAppEnvironment *SnykAppEnvironment
}

func NewUserAgentMiddleware(
	config configuration.Configuration,
	roundTripper http.RoundTripper,
	snykAppEnvironment *SnykAppEnvironment,
) *UserAgentMiddleware {
	return &UserAgentMiddleware{
		next:               roundTripper,
		config:             config,
		snykAppEnvironment: snykAppEnvironment,
	}
}

func (n *UserAgentMiddleware) RoundTrip(request *http.Request) (*http.Response, error) {
	apiUrl := n.config.GetString(configuration.API_URL)
	isSnykApi, err := IsSnykApi(apiUrl, request.URL, nil)
	if err != nil {
		return n.next.RoundTrip(request)
	}

	newRequest := request.Clone(request.Context())
	if n.snykAppEnvironment != nil && isSnykApi {
		newRequest.Header.Add("User-Agent", n.snykAppEnvironment.ToUserAgentHeader())
	}

	return n.next.RoundTrip(newRequest)
}
