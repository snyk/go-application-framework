package networking

import (
	"crypto/x509"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/rs/zerolog"
	"github.com/snyk/go-httpauth/pkg/httpauth"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking/certs"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
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
	// AddRootCAs adds the root CAs from the given PEM file.
	AddRootCAs(pemFileLocation string) error
	// GetAuthenticator returns the authenticator.
	GetAuthenticator() auth.Authenticator
	SetLogger(logger *zerolog.Logger)
}

// networkImpl is the default implementation of the NetworkAccess interface.
type networkImpl struct {
	config       configuration.Configuration
	staticHeader http.Header
	proxy        func(req *http.Request) (*url.URL, error)
	caPool       *x509.CertPool
	logger       *zerolog.Logger
}

// defaultHeadersRoundTripper is a custom http.RoundTripper which decorates the request with default headers.
type defaultHeadersRoundTripper struct {
	encapsulatedRoundTripper http.RoundTripper
	networkAccess            *networkImpl
}

func (rt *defaultHeadersRoundTripper) logRoundTrip(request *http.Request, response *http.Response, err error) {
	if rt.networkAccess == nil && rt.networkAccess.logger == nil {
		return
	}

	logHeader := http.Header{}
	loglevel := zerolog.TraceLevel

	if rt.networkAccess.logger.GetLevel() == loglevel {
		for i, v := range request.Header {
			for _, value := range v {
				if strings.ToLower(i) == "authorization" || strings.ToLower(i) == "session-token" {
					authHeader := strings.Split(value, " ")
					if len(authHeader) == 2 && len(authHeader[1]) > 4 {
						value = authHeader[0] + " " + authHeader[1][0:4] + "***"
					} else {
						value = "***"
					}
				}
				logHeader.Add(i, value)
			}
		}
	}

	rt.networkAccess.logger.WithLevel(loglevel).Msgf("> request: %s, %s, %v", request.Method, request.URL.String(), logHeader)

	if response != nil {
		rt.networkAccess.logger.WithLevel(loglevel).Msgf("< response: %d, %v", response.StatusCode, response.Header)
	}

	if err != nil {
		rt.networkAccess.logger.WithLevel(loglevel).Msgf("< error: %s", err.Error())
	}
}

// RoundTrip is an implementation of the http.RoundTripper interface.
func (rt *defaultHeadersRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	newRequest := request.Clone(request.Context())
	rt.networkAccess.addDefaultHeader(newRequest)
	response, err := rt.encapsulatedRoundTripper.RoundTrip(newRequest)

	rt.logRoundTrip(newRequest, response, err)

	return response, err
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

func (n *networkImpl) getUnauthorizedRoundTripper() http.RoundTripper {
	transport := http.DefaultTransport.(*http.Transport)
	rt := defaultHeadersRoundTripper{
		networkAccess:            n,
		encapsulatedRoundTripper: n.configureRoundTripper(transport),
	}
	return &rt
}

func (n *networkImpl) GetRoundTripper() http.RoundTripper {
	rt := n.getUnauthorizedRoundTripper()
	return middleware.NewAuthHeaderMiddleware(n.config, n.GetAuthenticator(), rt)
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
	client.Transport = n.getUnauthorizedRoundTripper()
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
	authClient := n.GetUnauthorizedHttpClient()
	return auth.CreateAuthenticator(n.config, authClient)
}

func (n *networkImpl) SetLogger(logger *zerolog.Logger) {
	n.logger = logger
}
