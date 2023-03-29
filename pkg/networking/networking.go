package networking

import (
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking/certs"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
	"github.com/snyk/go-httpauth/pkg/httpauth"
)

//go:generate $GOPATH/bin/mockgen -source=networking.go -destination ../mocks/networking.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/networking/

// NetworkAccess is the interface for network access.
type NetworkAccess interface {
	// AddHeaders adds all the custom and authentication headers to the request.
	AddHeaders(request *http.Request) error
	// GetRoundTripper returns the http.RoundTripper.
	GetRoundTripper() http.RoundTripper
	// GetHttpClient returns the http client.
	GetHttpClient() *http.Client
	// GetUnauthorizedHttpClient returns an HTTP client that does not use authentication headers.
	GetUnauthorizedHttpClient() *http.Client
	// AddHeaderField adds a header field to the default header.
	AddHeaderField(key, value string)
	// AddRootCAs adds the root CAs from the given PEM file.
	AddRootCAs(pemFileLocation string) error
	// GetAuthenticator returns the authenticator.
	GetAuthenticator() auth.Authenticator
}

// networkImpl is the default implementation of the NetworkAccess interface.
type networkImpl struct {
	config        configuration.Configuration
	staticHeader  http.Header
	logger        *log.Logger
	proxy         func(req *http.Request) (*url.URL, error)
	caPool        *x509.CertPool
	authenticator auth.Authenticator
}

// customRoundTripper is a custom http.RoundTripper which decorates the request with default headers.
type customRoundTripper struct {
	encapsulatedRoundTripper http.RoundTripper
	networkAccess            *networkImpl
}

// RoundTrip is an implementation of the http.RoundTripper interface.
func (crt *customRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	crt.networkAccess.addDefaultHeader(request)
	return crt.encapsulatedRoundTripper.RoundTrip(request)
}

// NewNetworkAccess returns a networkImpl instance.
func NewNetworkAccess(config configuration.Configuration) NetworkAccess {
	// prepare logger
	logger := log.New(os.Stderr, "NetworkAccess - ", config.GetInt(configuration.DEBUG_FORMAT))
	if !config.GetBool(configuration.DEBUG) {
		logger.SetOutput(io.Discard)
	}

	return &networkImpl{
		config:       config,
		staticHeader: http.Header{},
		logger:       logger,
		proxy:        http.ProxyFromEnvironment,
	}
}

func (n *networkImpl) AddHeaderField(key, value string) {
	n.staticHeader.Add(key, value)
}

func (n *networkImpl) AddHeaders(request *http.Request) error {
	n.addDefaultHeader(request)
	return middleware.AddAuthenticationHeader(n.GetAuthenticator(), n.config, request)
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

func (n *networkImpl) GetRoundTripper() http.RoundTripper {
	transport := n.configureRoundTripper(http.DefaultTransport.(*http.Transport))

	rt := middleware.NewAuthHeaderMiddleware(n.config, n.GetAuthenticator(), transport)

	// encapsulate everything
	roundTrip := customRoundTripper{
		encapsulatedRoundTripper: rt,
		networkAccess:            n,
	}
	return &roundTrip
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
	if n.authenticator == nil {
		transport := n.configureRoundTripper(http.DefaultTransport.(*http.Transport))
		n.authenticator = n.createAuthenticator(transport)
	}

	return n.authenticator
}
