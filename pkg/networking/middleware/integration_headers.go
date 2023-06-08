package middleware

import (
	"net/http"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

type IntegrationHeaderMiddleware struct {
	next   http.RoundTripper
	config configuration.Configuration
}

func NewIntegrationHeaderMiddleware(
	config configuration.Configuration,
	roundTripper http.RoundTripper,
) *IntegrationHeaderMiddleware {
	return &IntegrationHeaderMiddleware{
		next:   roundTripper,
		config: config,
	}
}

func (n *IntegrationHeaderMiddleware) RoundTrip(request *http.Request) (*http.Response, error) {
	name := n.config.GetString(configuration.INTEGRATION_NAME)
	version := n.config.GetString(configuration.INTEGRATION_VERSION)
	request.Header.Add("x-snyk-integration", name+"/"+version)

	return n.next.RoundTrip(request)
}
