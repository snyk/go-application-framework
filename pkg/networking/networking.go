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

const (
	defaultUserAgent string = "snyk-cli"
)

// NetworkAccess is the interface for network access.
type NetworkAccess interface {
	// AddHeaders adds all the custom and authentication headers to the request.
	AddHeaders(request *http.Request) error
	// AddDefaultHeader adds the default headers request.
	AddDefaultHeader(request *http.Request) error
	// GetDefaultHeader returns the default header for a given URL.
	GetDefaultHeader(url *url.URL) http.Header
	// GetRoundTripper returns the http.RoundTripper.
	GetRoundTripper() http.RoundTripper
	// GetHttpClient returns the http client.
	GetHttpClient() *http.Client
	// GetUnauthorizedHttpClient returns an HTTP client that does not use authentication headers.
	GetUnauthorizedHttpClient() *http.Client
	// AddHeaderField adds a header field to the default header.
	AddHeaderField(key string, value string)
	// AddRootCAs adds the root CAs from the given PEM file.
	AddRootCAs(pemFileLocation string) error
	// GetAuthenticator returns the authenticator.
	GetAuthenticator() auth.Authenticator
}

// NetworkImpl is the default implementation of the NetworkAccess interface.
type NetworkImpl struct {
	config        configuration.Configuration
	userAgent     string
	staticHeader  http.Header
	logger        *log.Logger
	proxy         func(req *http.Request) (*url.URL, error)
	caPool        *x509.CertPool
	authenticator auth.Authenticator
}

// customRoundTripper is a custom http.RoundTripper which decorates the request with default headers.
type customRoundTripper struct {
	encapsulatedRoundTripper http.RoundTripper
	networkAccess            NetworkAccess
}

// RoundTrip is an implementation of the http.RoundTripper interface.
func (crt *customRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	_ = crt.networkAccess.AddDefaultHeader(request)
	return crt.encapsulatedRoundTripper.RoundTrip(request)
}

// NewNetworkAccess returns a NetworkImpl instance.
func NewNetworkAccess(config configuration.Configuration) NetworkAccess {
	// prepare logger
	logger := log.New(os.Stderr, "NetworkAccess - ", config.GetInt(configuration.DEBUG_FORMAT))
	if config.GetBool(configuration.DEBUG) == false {
		logger.SetOutput(io.Discard)
	}

	c := NetworkImpl{
		config:       config,
		userAgent:    defaultUserAgent,
		staticHeader: http.Header{},
		logger:       logger,
		proxy:        http.ProxyFromEnvironment,
	}

	return &c
}

func (n *NetworkImpl) AddHeaderField(key string, value string) {
	n.staticHeader[key] = append(n.staticHeader[key], value)
}

func (n *NetworkImpl) AddHeaders(request *http.Request) error {
	if err := n.AddDefaultHeader(request); err != nil {
		return err
	}
	if err := n.GetAuthenticator().AddAuthenticationHeader(request); err != nil {
		return err
	}
	return nil
}

// AddDefaultHeader adds the default headers request.
func (n *NetworkImpl) AddDefaultHeader(request *http.Request) error {
	defaultHeader := http.Header{"User-Agent": {n.userAgent}}

	// add static header
	for k, v := range n.staticHeader {
		for i := range v {
			defaultHeader.Add(k, v[i])
		}
	}

	// iterate over default headers and add them if there is no existing entry yet
	for k, v := range defaultHeader {
		for i := range v {
			request.Header.Set(k, v[i])
		}
	}

	return nil
}

func (n *NetworkImpl) GetDefaultHeader(url *url.URL) http.Header {
	tmpRequest := &http.Request{
		Header: http.Header{},
		URL:    url,
	}

	_ = n.AddDefaultHeader(tmpRequest)

	return tmpRequest.Header
}

func (n *NetworkImpl) GetRoundTripper() http.RoundTripper {
	transport := n.configureRoundTripper(http.DefaultTransport.(*http.Transport))
	n.authenticator = n.createAuthenticator(transport)

	rt := middleware.NewAuthHeaderMiddleware(n.config, n.authenticator, transport)

	// encapsulate everything
	roundTrip := customRoundTripper{
		encapsulatedRoundTripper: rt,
		networkAccess:            n,
	}
	return &roundTrip
}

func (n *NetworkImpl) createAuthenticator(transport *http.Transport) auth.Authenticator {
	authClient := *http.DefaultClient
	authClient.Transport = transport.Clone()
	return auth.CreateAuthenticator(n.config, &authClient)
}

func (n *NetworkImpl) configureRoundTripper(base *http.Transport) *http.Transport {
	// configure insecure
	insecure := n.config.GetBool(configuration.INSECURE_HTTPS)
	authenticationMechanism := httpauth.AuthenticationMechanismFromString(n.config.GetString(configuration.PROXY_AUTHENTICATION_MECHANISM))
	transport := base.Clone()
	transport = middleware.ApplyTlsConfig(transport, insecure, n.caPool)
	transport = middleware.ConfigureProxy(transport, n.logger, n.proxy, authenticationMechanism)
	return transport
}

func (n *NetworkImpl) GetHttpClient() *http.Client {
	client := *http.DefaultClient
	client.Transport = n.GetRoundTripper()
	return &client
}

func (n *NetworkImpl) GetUnauthorizedHttpClient() *http.Client {
	client := *http.DefaultClient
	client.Transport = n.configureRoundTripper(http.DefaultTransport.(*http.Transport))
	return &client
}

func (n *NetworkImpl) AddRootCAs(pemFileLocation string) error {
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

func (n *NetworkImpl) GetAuthenticator() auth.Authenticator {
	if n.authenticator == nil {
		transport := n.configureRoundTripper(http.DefaultTransport.(*http.Transport))
		n.authenticator = n.createAuthenticator(transport)
	}

	return n.authenticator
}
