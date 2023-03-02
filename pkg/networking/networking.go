package networking

import (
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/snyk/go-application-framework/internal/constants"
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
	// AddDefaultHeader adds the default headers request.
	AddDefaultHeader(request *http.Request) error
	// GetDefaultHeader returns the default header for a given URL.
	GetDefaultHeader(url *url.URL) http.Header
	// GetRoundTripper returns the http.RoundTripper.
	GetRoundTripper() http.RoundTripper
	// GetHttpClient returns the http client.
	GetHttpClient() *http.Client
	// AddHeaderField adds a header field to the default header.
	AddHeaderField(key string, value string)
	// AddRootCAs adds the root CAs from the given PEM file.
	AddRootCAs(pemFileLocation string) error
}

// NetworkImpl is the default implementation of the NetworkAccess interface.
type NetworkImpl struct {
	config       configuration.Configuration
	userAgent    string
	staticHeader http.Header
	logger       *log.Logger
	proxy        func(req *http.Request) (*url.URL, error)
	caPool       *x509.CertPool
}

// customRoundtripper is a custom http.RoundTripper which decorates the request with default headers.
type customRoundtripper struct {
	encapsulatedRoundtripper http.RoundTripper
	networkAccess            NetworkAccess
}

// RoundTrip is an implementation of the http.RoundTripper interface.
func (crt *customRoundtripper) RoundTrip(request *http.Request) (*http.Response, error) {
	_ = crt.networkAccess.AddDefaultHeader(request)
	return crt.encapsulatedRoundtripper.RoundTrip(request)
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

	if request.URL != nil {
		// determine configured api url
		apiUrlString := n.config.GetString(configuration.API_URL)
		apiUrl, err := url.Parse(apiUrlString)
		if err != nil {
			apiUrl, _ = url.Parse(constants.SNYK_DEFAULT_API_URL)
		}

		// requests to the api automatically get an authentication token attached
		if strings.Contains(request.URL.Host, apiUrl.Host) {
			err = auth.NewTokenAuthenticator(func() string { return auth.GetAuthHeader(n.config) }).Authorize(request)
			if err != nil {
				return err
			}
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
	// configure insecure
	insecure := n.config.GetBool(configuration.INSECURE_HTTPS)
	authenticationMechanism := httpauth.AuthenticationMechanismFromString(n.config.GetString(configuration.PROXY_AUTHENTICATION_MECHANISM))

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport = middleware.ApplyTlsConfig(transport, insecure, n.caPool)
	transport = middleware.ConfigureProxy(transport, n.logger, n.proxy, authenticationMechanism)

	authClient := *http.DefaultClient
	authClient.Transport = transport.Clone()
	authenticator := auth.CreateAuthenticator(n.config, &authClient)

	rt := middleware.NewAuthHeaderMiddleware(n.config, authenticator, transport)

	// encapsulate everything
	roundTrip := customRoundtripper{
		encapsulatedRoundtripper: rt,
		networkAccess:            n,
	}
	return &roundTrip
}

func (n *NetworkImpl) GetHttpClient() *http.Client {
	client := *http.DefaultClient
	client.Transport = n.GetRoundTripper()
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
