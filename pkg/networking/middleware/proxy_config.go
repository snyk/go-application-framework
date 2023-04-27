package middleware

import (
	"log"
	"net/http"
	"net/url"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-httpauth/pkg/httpauth"
)

func ConfigureProxy(
	transport *http.Transport,
	logger *zerolog.Logger,
	proxy func(req *http.Request) (*url.URL, error),
	authenticationMechanism httpauth.AuthenticationMechanism,
) *http.Transport {
	transport = transport.Clone()

	// create proxy authenticator if required
	var proxyAuthenticator *httpauth.ProxyAuthenticator
	if httpauth.IsSupportedMechanism(authenticationMechanism) {
		proxyAuthenticator = httpauth.NewProxyAuthenticator(authenticationMechanism, proxy, log.New(&utils.ToZeroLogDebug{Logger: logger}, "", 0))
		transport.DialContext = proxyAuthenticator.DialContext
		transport.Proxy = nil
	} else {
		transport.DialContext = nil
		transport.Proxy = proxy
	}
	return transport
}
