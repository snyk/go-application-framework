package connectivity

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
)

// Checker performs connectivity checks to Snyk endpoints
type Checker struct {
	networkAccess networking.NetworkAccess
	logger        *zerolog.Logger
	config        configuration.Configuration
	timeout       time.Duration
	apiClient     api.ApiClient
}

// NewChecker creates a new connectivity checker
func NewChecker(networkAccess networking.NetworkAccess, logger *zerolog.Logger, config configuration.Configuration) *Checker {
	// Initialize API client
	apiUrl := config.GetString(configuration.API_URL)
	if apiUrl == "" {
		apiUrl = "https://api.snyk.io"
	}
	httpClient := networkAccess.GetHttpClient()
	apiClient := api.NewApi(apiUrl, httpClient)

	return &Checker{
		networkAccess: networkAccess,
		logger:        logger,
		config:        config,
		timeout:       10 * time.Second,
		apiClient:     apiClient,
	}
}

// NewCheckerWithApiClient creates a new connectivity checker with a custom API client (useful for testing)
func NewCheckerWithApiClient(networkAccess networking.NetworkAccess, logger *zerolog.Logger, config configuration.Configuration, apiClient api.ApiClient) *Checker {
	return &Checker{
		networkAccess: networkAccess,
		logger:        logger,
		config:        config,
		timeout:       10 * time.Second,
		apiClient:     apiClient,
	}
}

// DetectProxyConfig detects proxy configuration from environment variables
func (c *Checker) DetectProxyConfig() ProxyConfig {
	config := ProxyConfig{}

	// Check proxy variables in priority order
	proxyVars := []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"}
	for _, varName := range proxyVars {
		if value := os.Getenv(varName); value != "" {
			if !config.Detected {
				config.Detected = true
				config.URL = value
				config.Variable = varName
			}
		}
	}

	// Check NO_PROXY
	if noProxy := os.Getenv("NO_PROXY"); noProxy != "" {
		config.NoProxy = noProxy
	} else if noProxy := os.Getenv("no_proxy"); noProxy != "" {
		config.NoProxy = noProxy
	}

	return config
}

// CheckOrganizations checks if authentication token is configured and fetches organizations
func (c *Checker) CheckOrganizations(endpoint string) ([]Organization, error) {
	// Check if token is available
	token := c.config.GetString(configuration.AUTHENTICATION_TOKEN)
	if token == "" {
		token = c.config.GetString(configuration.AUTHENTICATION_BEARER_TOKEN)
	}
	if token == "" {
		oauthToken, err := auth.GetOAuthToken(c.config)
		if err == nil && oauthToken != nil {
			token = oauthToken.AccessToken
		}
	}

	// If no token, return nil (no organizations to fetch)
	if token == "" {
		return nil, nil
	}

	response, err := c.apiClient.GetOrganizations(100)
	if err != nil {
		return nil, err
	}

	defaultOrgId, err := c.apiClient.GetDefaultOrgId()
	if err != nil {
		// default org is optional, don't fail the entire operation
		c.logger.Debug().Err(err).Msg("Failed to get default organization ID")
		defaultOrgId = ""
	}

	var orgs []Organization
	for _, org := range response.Organizations {
		// Convert to our Organization type
		orgs = append(orgs, Organization{
			ID:        org.Id,
			Name:      org.Attributes.Name,
			IsDefault: org.Id == defaultOrgId,
		})
	}

	return orgs, nil
}

// CheckConnectivity performs connectivity checks to all Snyk endpoints
func (c *Checker) CheckConnectivity() (*ConnectivityCheckResult, error) {
	result := &ConnectivityCheckResult{
		StartTime: time.Now(),
	}

	result.ProxyConfig = c.DetectProxyConfig()

	for _, host := range GetSnykHosts() {
		hostResult := c.checkHost(host)
		result.HostResults = append(result.HostResults, hostResult)

		c.generateTODOs(result, &hostResult)
	}

	token := c.config.GetString(configuration.AUTHENTICATION_TOKEN)
	if token != "" {
		c.logger.Info().Msg("API Token found")
	}
	if token == "" {
		token = c.config.GetString(configuration.AUTHENTICATION_BEARER_TOKEN)
		if token != "" {
			c.logger.Info().Msg("Bearer Token found")
		}
	}

	if token == "" {
		oauthToken, err := auth.GetOAuthToken(c.config)
		if err == nil && oauthToken != nil && oauthToken.AccessToken != "" {
			c.logger.Info().Msg("OAuth Token found")
			token = oauthToken.AccessToken
		}
	}

	result.TokenPresent = token != ""

	if result.TokenPresent {
		apiEndpoint := c.config.GetString(configuration.API_URL)
		if apiEndpoint == "" {
			apiEndpoint = "https://api.snyk.io"
		}

		orgs, err := c.CheckOrganizations(apiEndpoint)
		if err != nil {
			result.OrgCheckError = err
		} else {
			result.Organizations = orgs
		}
	}

	result.EndTime = time.Now()
	return result, nil
}

// checkHost performs connectivity check for a single host
func (c *Checker) checkHost(host string) HostResult {
	result := HostResult{
		Host: host,
	}

	// need to extract only the host part for display
	displayHost := host
	if idx := strings.Index(displayHost, "/"); idx != -1 {
		displayHost = displayHost[:idx]
	}
	if idx := strings.Index(displayHost, ":"); idx != -1 {
		displayHost = displayHost[:idx]
	}
	result.DisplayHost = displayHost

	result.URL = "https://" + host

	httpClient := c.networkAccess.GetUnauthorizedHttpClient()
	startTime := time.Now()
	resp, err := httpClient.Get(result.URL)
	result.ResponseTime = time.Since(startTime)

	if err != nil {
		result.Error = err
		result.Status = c.categorizeError(err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		result.Status = StatusOK
	case http.StatusForbidden, http.StatusNotFound:
		result.Status = StatusReachable
	case http.StatusProxyAuthRequired:
		proxyAuth := resp.Header.Get("Proxy-Authenticate")
		result.ProxyAuth = proxyAuth
		if strings.Contains(strings.ToLower(proxyAuth), "negotiate") ||
			strings.Contains(strings.ToLower(proxyAuth), "basic") {
			result.Status = StatusProxyAuthSupported
		} else {
			result.Status = StatusProxyAuthUnsupported
		}
	default:
		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			result.Status = StatusServerError
		} else {
			result.Status = StatusBlocked
		}
	}

	return result
}

// categorizeError categorizes network errors
func (c *Checker) categorizeError(err error) ConnectionStatus {
	errStr := strings.ToLower(err.Error())

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return StatusDNSError
	}
	if strings.Contains(errStr, "no such host") {
		return StatusDNSError
	}

	if os.IsTimeout(err) || strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "deadline exceeded") {
		return StatusTimeout
	}

	if strings.Contains(errStr, "tls") || strings.Contains(errStr, "ssl") ||
		strings.Contains(errStr, "certificate") || strings.Contains(errStr, "x509") {
		return StatusTLSError
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return StatusTimeout
		}
	}

	return StatusBlocked
}

// generateTODOs generates actionable TODOs based on host result
func (c *Checker) generateTODOs(result *ConnectivityCheckResult, hostResult *HostResult) {
	switch hostResult.Status {
	case StatusOK:
		// successful connections don't need any action
	case StatusReachable:
		result.AddTODOf(TodoWarn, "Host '%s' is reachable but returned HTTP %d. This is expected for some endpoints when accessed directly via browser/curl.",
			hostResult.DisplayHost, hostResult.StatusCode)

	case StatusProxyAuthSupported:
		if strings.Contains(strings.ToLower(hostResult.ProxyAuth), "negotiate") {
			result.AddTODOf(TodoInfo, "Proxy requires 'Negotiate' authentication for '%s'. This is supported by Snyk CLI. Ensure you are logged into your domain for SSO to work.",
				hostResult.DisplayHost)
		} else {
			result.AddTODOf(TodoWarn, "Proxy requires 'Basic' authentication for '%s'. While this may work, it is not the officially documented SSO method ('Negotiate') and may be less secure or reliable.",
				hostResult.DisplayHost)
		}

	case StatusProxyAuthUnsupported:
		result.AddTODOf(TodoFail, "Your proxy requires an unsupported authentication scheme for '%s'. Snyk CLI supports 'Negotiate'. Please contact your proxy team to enable 'Negotiate' for the snyk.io domain.",
			hostResult.DisplayHost)

	case StatusServerError:
		result.AddTODOf(TodoFail, "Server error (HTTP %d) when connecting to '%s'. This may be temporary. Try again later or contact Snyk support if it persists.",
			hostResult.StatusCode, hostResult.DisplayHost)

	case StatusDNSError:
		result.AddTODOf(TodoFail, "DNS resolution failed for '%s'. Check your DNS settings or contact your network team.",
			hostResult.DisplayHost)

	case StatusTLSError:
		result.AddTODOf(TodoFail, "TLS/SSL error connecting to '%s'. Your system may be using an outdated TLS version or have certificate validation issues. Ensure TLS 1.2 is enabled.",
			hostResult.DisplayHost)

	case StatusTimeout:
		result.AddTODOf(TodoFail, "Connection to '%s' timed out. This may indicate a firewall blocking the connection.",
			hostResult.DisplayHost)

	case StatusBlocked:
		if hostResult.Error != nil {
			result.AddTODOf(TodoFail, "Connection to '%s' failed: %v. This may be a firewall, DNS, or proxy address issue. Contact your network team to allow HTTPS/443 access to this host and other required Snyk endpoints.",
				hostResult.DisplayHost, hostResult.Error)
		} else {
			result.AddTODOf(TodoFail, "Received HTTP status '%d' when connecting to '%s'. This may indicate a network block. Contact your network team.",
				hostResult.StatusCode, hostResult.DisplayHost)
		}
	}
}
