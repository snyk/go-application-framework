package networking

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/url"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking/certs"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
	"github.com/snyk/go-httpauth/pkg/httpauth"
)

//go:generate $GOPATH/bin/mockgen -source=networking.go -destination ../mocks/networking.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/networking/

// NetworkAccess is the interface for network access.
// It provides methods to get an HTTP client with default behaviors that handle authentication headers for Snyk API calls.
type NetworkAccess interface {
	// AddHeaders adds all the custom and authentication headers to the request.
	AddHeaders(request *http.Request) error
	// GetRoundTripper returns the http.RoundTripper that is used by the http.Client.
	GetRoundTripper() http.RoundTripper
	// GetHttpClient returns the http client.
	GetHttpClient() *http.Client
	// GetUnauthorizedHttpClient returns an HTTP client that does not use authentication headers.
	GetUnauthorizedHttpClient() *http.Client
	// AddHeaderField adds a header field to the default header.
	AddHeaderField(key, value string)
	// SetUserAgent sets the user agent header according to the Snyk environment.
	// The format is the following pattern:
	// <app>/<appVer> (<os>;<arch>;<procName>) <integration>/<integrationVersion> (<integrationEnv>/<integrationEnvVersion>)
	// The header will only be present when sending requests to the snyk API
	SetUserAgent(userAgent middleware.SnykAppEnvironment) error
	// AddRootCAs adds the root CAs from the given PEM file.
	AddRootCAs(pemFileLocation string) error
	// GetAuthenticator returns the authenticator.
	GetAuthenticator() auth.Authenticator
	SetLogger(logger *zerolog.Logger)
}

// networkImpl is the default implementation of the NetworkAccess interface.
type networkImpl struct {
	config             configuration.Configuration
	staticHeader       http.Header
	proxy              func(req *http.Request) (*url.URL, error)
	caPool             *x509.CertPool
	logger             *zerolog.Logger
	snykAppEnvironment *middleware.SnykAppEnvironment
}

// DefaultHeadersRoundTripper is a custom http.RoundTripper which decorates the request with default headers.
type DefaultHeadersRoundTripper struct {
	encapsulatedRoundTripper http.RoundTripper
	networkAccess            *networkImpl
}

// RoundTrip is an implementation of the http.RoundTripper interface.
func (rt *DefaultHeadersRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	newRequest := request.Clone(request.Context())
	rt.networkAccess.addDefaultHeader(newRequest)
	return rt.encapsulatedRoundTripper.RoundTrip(newRequest)
}

// NewNetworkAccess returns a networkImpl instance.
func NewNetworkAccess(config configuration.Configuration) NetworkAccess {
	// prepare logger
	logger := zerolog.New(io.Discard)

	n := &networkImpl{
		config:       config,
		staticHeader: http.Header{},
		logger:       &logger,
		proxy:        http.ProxyFromEnvironment,
	}

	extraCaCertFile := config.GetString(configuration.ADD_TRUSTED_CA_FILE)
	if len(extraCaCertFile) > 0 {
		err := n.AddRootCAs(extraCaCertFile)
		if err != nil {
			logger.Printf("Failed to AddRootCAs from '%s' (%v)\n", extraCaCertFile, err)
		} else {
			logger.Print("Using additional CAs from file:", extraCaCertFile)
		}
	}

	return n
}

func (n *networkImpl) AddHeaderField(key, value string) {
	n.staticHeader.Add(key, value)
}

// A middleware that captures the headers of the request and doesn't send it
type headerCapture struct {
	capturedHeaders map[string]string
}

func (h *headerCapture) RoundTrip(request *http.Request) (*http.Response, error) {
	h.capturedHeaders = make(map[string]string)
	for k, v := range request.Header {
		h.capturedHeaders[k] = v[0]
	}
	return nil, nil
}

func (n *networkImpl) AddHeaders(request *http.Request) error {
	n.addDefaultHeader(request)
	hc := &headerCapture{}
	var rt http.RoundTripper = hc
	rt = n.addMiddlewaresToRoundTripper(rt)
	_, err := rt.RoundTrip(request)
	for k, v := range hc.capturedHeaders {
		request.Header.Set(k, v)
	}

	return err
}

func (n *networkImpl) SetUserAgent(userAgent middleware.SnykAppEnvironment) error {
	// n.staticHeader.Set("User-Agent", userAgent.ToUserAgentHeader())
	n.snykAppEnvironment = &userAgent
	return nil
}

// addDefaultHeader adds the default headers request.
func (n *networkImpl) addDefaultHeader(request *http.Request) {
	// add/replace request headers by default headers
	for k, v := range n.staticHeader {
		request.Header.Del(k)
		for i := range v {
			request.Header.Add(k, v[i])
		}
	}
}

func (n *networkImpl) addMiddlewaresToRoundTripper(rt http.RoundTripper) http.RoundTripper {
	rt = middleware.NewAuthHeaderMiddleware(n.config, n.GetAuthenticator(), rt)
	rt = middleware.NewUserAgentMiddleware(n.config, rt, n.snykAppEnvironment)
	roundTrip := DefaultHeadersRoundTripper{
		encapsulatedRoundTripper: rt,
		networkAccess:            n,
	}
	return &roundTrip
}

func (n *networkImpl) GetRoundTripper() http.RoundTripper {
	rt := n.configureRoundTripper(http.DefaultTransport.(*http.Transport))
	return n.addMiddlewaresToRoundTripper(rt)
}

func (n *networkImpl) createAuthenticator(transport *http.Transport) auth.Authenticator {
	authClient := *http.DefaultClient
	authClient.Transport = transport.Clone()
	return auth.CreateAuthenticator(n.config, &authClient)
}

func (n *networkImpl) configureRoundTripper(base *http.Transport) *http.Transport {
	// configure insecure
	insecure := n.config.GetBool(configuration.INSECURE_HTTPS)
	authenticationMechanism := httpauth.AuthenticationMechanismFromString(n.config.GetString(configuration.PROXY_AUTHENTICATION_MECHANISM))
	transport := base.Clone()
	transport = middleware.ApplyTlsConfig(transport, insecure, n.caPool)
	transport = middleware.ConfigureProxy(transport, n.logger, n.proxy, authenticationMechanism)
	return transport
}

func (n *networkImpl) GetHttpClient() *http.Client {
	client := *http.DefaultClient
	client.Transport = n.GetRoundTripper()
	return &client
}

func (n *networkImpl) GetUnauthorizedHttpClient() *http.Client {
	client := *http.DefaultClient
	client.Transport = n.configureRoundTripper(http.DefaultTransport.(*http.Transport))
	return &client
}

func (n *networkImpl) AddRootCAs(pemFileLocation string) error {
	var err error

	if len(pemFileLocation) > 0 {
		if n.caPool == nil {
			n.caPool, err = x509.SystemCertPool()
		}

		if err == nil {
			err = certs.AddCertificatesToPool(n.caPool, pemFileLocation)
		}
	}

	return err
}

func (n *networkImpl) GetAuthenticator() auth.Authenticator {
	transport := n.configureRoundTripper(http.DefaultTransport.(*http.Transport))
	return n.createAuthenticator(transport)
}

func (n *networkImpl) SetLogger(logger *zerolog.Logger) {
	n.logger = logger
}
