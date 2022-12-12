package networking

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-httpauth/pkg/httpauth"
)

//go:generate $GOPATH/bin/mockgen -source=networking.go -destination ../mocks/networking.go -package mocks -self_package github.com/snyk/go-application-framework/pkg/networking/

const (
	defaultUserAgent           string = "snyk-cli"
	HEADER_FIELD_AUTHORIZATION string = "Authorization"
	HEADER_FIELD_USER_AGENT    string = "User-Agent"
)

type NetworkAccess interface {
	GetDefaultHeader(url *url.URL) http.Header
	GetRoundtripper() http.RoundTripper
	GetHttpClient() *http.Client
	AddHeaderField(key string, value string)
	RemoveHeaderFieldForUrl(url *url.URL, key string)
}

type NetworkImpl struct {
	config                configuration.Configuration
	userAgent             string
	staticHeader          http.Header
	logger                *log.Logger
	proxy                 func(req *http.Request) (*url.URL, error)
	ignoreHeaderForUrlMap map[string][]*url.URL
}

type customRoundtripper struct {
	encapsulatedRoundtripper *http.Transport
	networkAccess            NetworkAccess
	proxyAuthenticator       *httpauth.ProxyAuthenticator
}

func (crt *customRoundtripper) decorateRequest(request *http.Request) *http.Request {
	defaultHeader := crt.networkAccess.GetDefaultHeader(request.URL)

	// iterate over default headers and add them if there is no existing entry yet
	for k, v := range defaultHeader {
		if _, found := request.Header[k]; found == false {
			for i := range v {
				request.Header.Add(k, v[i])
			}
		}
	}

	return request
}

func (crt *customRoundtripper) RoundTrip(request *http.Request) (*http.Response, error) {
	request = crt.decorateRequest(request)
	return crt.encapsulatedRoundtripper.RoundTrip(request)
}

func NewNetworkAccess(config configuration.Configuration) NetworkAccess {
	// prepare logger
	logger := log.New(os.Stderr, "NetworkAccess - ", config.GetInt(configuration.DEBUG_FORMAT))
	if config.GetBool(configuration.DEBUG) == false {
		logger.SetOutput(io.Discard)
	}

	c := NetworkImpl{
		config:                config,
		userAgent:             defaultUserAgent,
		staticHeader:          http.Header{},
		logger:                logger,
		proxy:                 http.ProxyFromEnvironment,
		ignoreHeaderForUrlMap: make(map[string][]*url.URL),
	}
	return &c
}

func (n *NetworkImpl) AddHeaderField(key string, value string) {
	n.staticHeader[key] = append(n.staticHeader[key], value)
}

func (n *NetworkImpl) GetDefaultHeader(url *url.URL) http.Header {
	result := http.Header{}

	// add static header
	for k, v := range n.staticHeader {
		for i := range v {
			result.Add(k, v[i])
		}
	}

	if url != nil {
		// determine configured api url
		apiUrlString := n.config.GetString(configuration.API_URL)
		apiUrl, err := url.Parse(apiUrlString)
		if err != nil {
			apiUrl, _ = url.Parse(constants.SNYK_DEFAULT_API_URL)
		}

		// requests to the api automatically get an authentication token attached
		if url.Host == apiUrl.Host {
			authHeader := GetAuthHeader(n.config)
			if len(authHeader) > 0 {
				result.Add(HEADER_FIELD_AUTHORIZATION, authHeader)
			}

		}
	}

	result.Add(HEADER_FIELD_USER_AGENT, n.userAgent)

	// remove fields from header if they have been added to the ignore list for the current url
	for headerField, urlList := range n.ignoreHeaderForUrlMap {
		for i := range urlList {
			if *urlList[i] == *url {
				result.Del(headerField)
				break
			}
		}
	}

	return result
}

func (n *NetworkImpl) GetRoundtripper() http.RoundTripper {
	// configure insecure
	insecure := n.config.GetBool(configuration.INSECURE_HTTPS)
	authenticationMechanism := httpauth.AuthenticationMechanismFromString(n.config.GetString(configuration.PROXY_AUTHENTICATION_MECHANISM))
	var proxyAuthenticator *httpauth.ProxyAuthenticator

	// create transport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
	}

	// create proxy authenticator if required
	if httpauth.IsSupportedMechanism(authenticationMechanism) {
		proxyAuthenticator = httpauth.NewProxyAuthenticator(authenticationMechanism, n.proxy, n.logger)
		transport.DialContext = proxyAuthenticator.DialContext
		transport.Proxy = nil
	} else {
		transport.DialContext = nil
		transport.Proxy = n.proxy
	}

	// encapsulate everything
	roundtrip := customRoundtripper{
		encapsulatedRoundtripper: transport,
		networkAccess:            n,
		proxyAuthenticator:       proxyAuthenticator,
	}
	return &roundtrip
}

func (n *NetworkImpl) GetHttpClient() *http.Client {
	client := *http.DefaultClient
	client.Transport = n.GetRoundtripper()
	return &client
}

func (n *NetworkImpl) RemoveHeaderFieldForUrl(value *url.URL, key string) {
	urlList, ok := n.ignoreHeaderForUrlMap[key]

	if !ok {
		urlList = make([]*url.URL, 0)
	}

	urlList = append(urlList, value)
	n.ignoreHeaderForUrlMap[key] = urlList
}
