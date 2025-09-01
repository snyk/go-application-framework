package connectivity

import (
	"fmt"
	"sync"
	"time"
)

// HostResult represents the connectivity test result for a single host
type HostResult struct {
	Host         string           `json:"host"`
	DisplayHost  string           `json:"displayHost"`
	URL          string           `json:"url"`
	StatusCode   int              `json:"statusCode"`
	Status       ConnectionStatus `json:"status"`
	Message      string           `json:"message,omitempty"`
	ProxyAuth    string           `json:"proxyAuth,omitempty"`
	ResponseTime time.Duration    `json:"responseTime"`
	Error        error            `json:"error,omitempty"`
}

// ConnectionStatus represents the status of a connection test
type ConnectionStatus int

const (
	StatusOK ConnectionStatus = iota
	StatusReachable
	StatusProxyAuthSupported
	StatusProxyAuthUnsupported
	StatusServerError
	StatusBlocked
	StatusDNSError
	StatusTLSError
	StatusTimeout
)

func (s ConnectionStatus) String() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusReachable:
		return "REACHABLE"
	case StatusProxyAuthSupported:
		return "PROXY AUTH REQUIRED (SUPPORTED)"
	case StatusProxyAuthUnsupported:
		return "PROXY AUTH REQUIRED (UNSUPPORTED)"
	case StatusServerError:
		return "SERVER ERROR"
	case StatusBlocked:
		return "BLOCKED"
	case StatusDNSError:
		return "DNS ERROR"
	case StatusTLSError:
		return "TLS/SSL ERROR"
	case StatusTimeout:
		return "TIMEOUT"
	default:
		return "UNKNOWN"
	}
}

// ProxyConfig represents proxy configuration detected from environment
type ProxyConfig struct {
	Detected bool   `json:"detected"`
	URL      string `json:"url,omitempty"`
	Variable string `json:"variable,omitempty"`
	NoProxy  string `json:"noProxy,omitempty"`
}

// TODO represents an actionable item from the connectivity check
type TODO struct {
	Level   TodoLevel `json:"level"`
	Message string    `json:"message"`
}

// TodoLevel represents the severity level of a TODO item
type TodoLevel int

const (
	TodoInfo TodoLevel = iota
	TodoWarn
	TodoFail
)

func (l TodoLevel) String() string {
	switch l {
	case TodoInfo:
		return "INFO"
	case TodoWarn:
		return "WARN"
	case TodoFail:
		return "FAIL"
	default:
		return "UNKNOWN"
	}
}

// ConnectivityCheckResult represents the complete result of connectivity checks
type ConnectivityCheckResult struct {
	ProxyConfig   ProxyConfig    `json:"proxyConfig"`
	HostResults   []HostResult   `json:"hostResults"`
	TODOs         []TODO         `json:"todos"`
	StartTime     time.Time      `json:"startTime"`
	EndTime       time.Time      `json:"endTime"`
	Organizations []Organization `json:"organizations"`
	TokenPresent  bool           `json:"tokenPresent"`
	OrgCheckError error          `json:"orgCheckError,omitempty"`
}

// AddTODOf adds a TODO item to the result with printf-style formatting
func (r *ConnectivityCheckResult) AddTODOf(level TodoLevel, format string, args ...interface{}) {
	r.TODOs = append(r.TODOs, TODO{
		Level:   level,
		Message: fmt.Sprintf(format, args...),
	})
}

// Organization represents a Snyk organization
type Organization struct {
	ID        string `json:"id"`
	GroupID   string `json:"groupId"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	IsDefault bool   `json:"isDefault"`
}

// snykHostsMutex protects access to SnykHosts
var snykHostsMutex sync.RWMutex

// SnykHosts contains all the Snyk endpoints to test
var SnykHosts = []string{
	"api.snyk.io",
	"app.snyk.io",
	"api.eu.snyk.io",
	"app.eu.snyk.io",
	"api.us.snyk.io",
	"app.us.snyk.io",
	"api.au.snyk.io",
	"app.au.snyk.io",
	"api.snykgov.io",
	"app.snykgov.io",
	"deeproxy.snyk.io/filters",
	"downloads.snyk.io:443/cli/wasm/bundle.tar.gz",
	"learn.snyk.io",
	"static.snyk.io/cli/latest/version",
	"snyk.io",
	"sentry.io",
}

// GetSnykHosts returns a copy of the current SnykHosts slice in a thread-safe manner
func GetSnykHosts() []string {
	snykHostsMutex.RLock()
	defer snykHostsMutex.RUnlock()

	// must return a copy to prevent external modification
	hosts := make([]string, len(SnykHosts))
	copy(hosts, SnykHosts)
	return hosts
}

// SetSnykHosts sets the SnykHosts slice in a thread-safe manner
func SetSnykHosts(hosts []string) {
	snykHostsMutex.Lock()
	defer snykHostsMutex.Unlock()

	// copy prevents modification of the slice after setting
	SnykHosts = make([]string, len(hosts))
	copy(SnykHosts, hosts)
}

// SetSnykHostsForTesting is a helper for tests that sets hosts and returns a cleanup function
func SetSnykHostsForTesting(hosts []string) func() {
	snykHostsMutex.Lock()
	originalHosts := make([]string, len(SnykHosts))
	copy(originalHosts, SnykHosts)

	SnykHosts = make([]string, len(hosts))
	copy(SnykHosts, hosts)
	snykHostsMutex.Unlock()

	// cleanup function restores the original hosts for test isolation
	return func() {
		snykHostsMutex.Lock()
		SnykHosts = originalHosts
		snykHostsMutex.Unlock()
	}
}
