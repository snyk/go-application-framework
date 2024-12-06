package networking

import (
	"bytes"
	"crypto/x509"
	"io"
	"net/http"
	"net/url"

	"github.com/rs/zerolog"

	"github.com/snyk/go-httpauth/pkg/httpauth"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking/certs"
	"github.com/snyk/go-application-framework/pkg/networking/middleware"
	networktypes "github.com/snyk/go-application-framework/pkg/networking/network_types"
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
	// AddDynamicHeaderField adds a dynamic header field to the request.
	AddDynamicHeaderField(key string, f DynamicHeaderFunc)
	// AddRootCAs adds the root CAs from the given PEM file.
	AddRootCAs(pemFileLocation string) error
	// AddErrorHandler registers an error handler for the underlying http.RoundTripper.
	AddErrorHandler(networktypes.ErrorHandlerFunc)
	// GetErrorHandler returns the registered error handler.
	GetErrorHandler() networktypes.ErrorHandlerFunc
	// GetAuthenticator returns the authenticator.
	GetAuthenticator() auth.Authenticator

	SetLogger(logger *zerolog.Logger)
	SetConfiguration(configuration configuration.Configuration)
	GetLogger() *zerolog.Logger
	GetConfiguration() configuration.Configuration

	Clone() NetworkAccess
}

type DynamicHeaderFunc func([]string) []string

// networkImpl is the default implementation of the NetworkAccess interface.
type networkImpl struct {
	config         configuration.Configuration
	staticHeader   http.Header
	dynamicHeaders map[string]DynamicHeaderFunc
	proxy          func(req *http.Request) (*url.URL, error)
	errorHandler   networktypes.ErrorHandlerFunc
	caPool         *x509.CertPool
	logger         *zerolog.Logger
}

const defaultNetworkLogLevel = zerolog.DebugLevel

func LogRequest(r *http.Request, logger *zerolog.Logger) {
	if logger.GetLevel() > defaultNetworkLogLevel { // Don't log if logger level is above the threshold
		return
	}

	logger.WithLevel(defaultNetworkLogLevel).Msgf("> request [%p]: %s %s", r, r.Method, r.URL.String())
	logger.WithLevel(defaultNetworkLogLevel).Msgf("> request [%p]: header: %v", r, r.Header)
}

func LogResponse(response *http.Response, logger *zerolog.Logger) {
	if logger.GetLevel() > defaultNetworkLogLevel { // Don't log if logger level is above the threshold
		return
	}

	if response != nil {
		logger.WithLevel(defaultNetworkLogLevel).Msgf("< response [%p]: %s", response.Request, response.Status)
		logger.WithLevel(defaultNetworkLogLevel).Msgf("< response [%p]: header: %v", response.Request, response.Header)

		// read body for error code
		if response.StatusCode >= 400 {
			bodyBytes, bodyErr := io.ReadAll(response.Body)
			if bodyErr == nil {
				response.Body.Close()
				response.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
				logger.WithLevel(defaultNetworkLogLevel).Msgf("< response [%p]: body: %v", response.Request, string(bodyBytes))
			} else {
				logger.WithLevel(defaultNetworkLogLevel).Err(bodyErr).Msgf("< response [%p]: Failed to read response body", response.Request)
			}
		}
	}
}

// defaultHeadersRoundTripper is a custom http.RoundTripper which decorates the request with default headers.
type defaultHeadersRoundTripper struct {
	encapsulatedRoundTripper http.RoundTripper
	networkAccess            *networkImpl
	logLevel                 zerolog.Level
}

func (rt *defaultHeadersRoundTripper) logRoundTrip(request *http.Request, response *http.Response, err error) {
	if rt.networkAccess == nil || rt.networkAccess.logger == nil || rt.networkAccess.logger.GetLevel() != rt.logLevel {
		return
	}

	LogRequest(request, rt.networkAccess.logger)
	LogResponse(response, rt.networkAccess.logger)

	if err != nil {
		rt.networkAccess.logger.WithLevel(rt.logLevel).Msgf("< error: %s", err.Error())
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

func (rt *defaultHeadersRoundTripper) SetLogLevel(level zerolog.Level) {
	rt.logLevel = level
}

// NewNetworkAccess returns a networkImpl instance.
func NewNetworkAccess(config configuration.Configuration) NetworkAccess {
	// prepare logger
	logger := zerolog.New(io.Discard)

	n := &networkImpl{
		config:         config,
		staticHeader:   http.Header{},
		logger:         &logger,
		proxy:          http.ProxyFromEnvironment,
		dynamicHeaders: map[string]DynamicHeaderFunc{},
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

// AddHeaderField enables to set static header field values to requests. Existing values will be replaced.
// For more flexibility, see AddDynamicHeaderField().
func (n *networkImpl) AddHeaderField(key, value string) {
	n.staticHeader.Add(key, value)
}

// AddErrorHandler registers an error handler for the underlying http.RoundTripper and registers the response middleware
// that maps non 2xx status codes to Error Catalog errors.
func (n *networkImpl) AddErrorHandler(handler networktypes.ErrorHandlerFunc) {
	n.errorHandler = handler
}

func (n *networkImpl) GetErrorHandler() networktypes.ErrorHandlerFunc {
	return n.errorHandler
}

// AddDynamicHeaderField enables to define functions that will be invoked when a header field is added to a request.
// The function receives a string slice of existing values and should return the final values associated to the header field.
// This function extends the possibilities that AddHeaderField() offers for static header fields.
func (n *networkImpl) AddDynamicHeaderField(key string, f DynamicHeaderFunc) {
	n.dynamicHeaders[key] = f
}

func (n *networkImpl) AddHeaders(request *http.Request) error {
	n.addDefaultHeader(request)
	return middleware.AddAuthenticationHeader(n.GetAuthenticator(), n.config, request)
}

// addDefaultHeader adds the default headers request.
func (n *networkImpl) addDefaultHeader(request *http.Request) {
	// add/replace request headers by dynamic headers
	for k, determineHeader := range n.dynamicHeaders {
		existingValues := request.Header.Values(k)
		newValues := determineHeader(existingValues)
		request.Header.Del(k)
		for _, nv := range newValues {
			request.Header.Add(k, nv)
		}
	}

	// add/replace request headers by default headers
	for k, v := range n.staticHeader {
		request.Header.Del(k)
		for i := range v {
			request.Header.Add(k, v[i])
		}
	}
}

func (n *networkImpl) getUnauthorizedRoundTripper() http.RoundTripper {
	//nolint:errcheck // breaking api change needed to fix this
	transport := http.DefaultTransport.(*http.Transport) //nolint:forcetypeassert // panic here is reasonable
	var crt http.RoundTripper = n.configureRoundTripper(transport)
	if n.errorHandler != nil {
		crt = middleware.NewReponseMiddleware(crt, n.config, n.errorHandler)
	}
	rt := defaultHeadersRoundTripper{
		networkAccess:            n,
		encapsulatedRoundTripper: crt,
		logLevel:                 defaultNetworkLogLevel,
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

func (n *networkImpl) SetConfiguration(configuration configuration.Configuration) {
	n.config = configuration
}

func (n *networkImpl) GetLogger() *zerolog.Logger {
	return n.logger
}

func (n *networkImpl) GetConfiguration() configuration.Configuration {
	return n.config
}

func (n *networkImpl) Clone() NetworkAccess {
	clone := &networkImpl{
		config:         n.config.Clone(),
		logger:         n.logger,
		staticHeader:   n.staticHeader.Clone(),
		dynamicHeaders: map[string]DynamicHeaderFunc{},
		proxy:          n.proxy,
		errorHandler:   n.errorHandler,
	}

	for key, dynHeaderFuncs := range n.dynamicHeaders {
		clone.dynamicHeaders[key] = dynHeaderFuncs
	}

	if n.caPool != nil {
		clone.caPool = n.caPool.Clone()
	}

	return clone
}
