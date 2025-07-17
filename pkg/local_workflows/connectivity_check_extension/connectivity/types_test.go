package connectivity

import (
	"testing"
	"time"
)

func TestConnectionStatus_String(t *testing.T) {
	tests := []struct {
		status   ConnectionStatus
		expected string
	}{
		{StatusOK, "OK"},
		{StatusReachable, "REACHABLE"},
		{StatusProxyAuthSupported, "PROXY AUTH REQUIRED (SUPPORTED)"},
		{StatusProxyAuthUnsupported, "PROXY AUTH REQUIRED (UNSUPPORTED)"},
		{StatusServerError, "SERVER ERROR"},
		{StatusBlocked, "BLOCKED"},
		{StatusDNSError, "DNS ERROR"},
		{StatusTLSError, "TLS/SSL ERROR"},
		{StatusTimeout, "TIMEOUT"},
		{ConnectionStatus(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.status.String()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestTodoLevel_String(t *testing.T) {
	tests := []struct {
		level    TodoLevel
		expected string
	}{
		{TodoInfo, "INFO"},
		{TodoWarn, "WARN"},
		{TodoFail, "FAIL"},
		{TodoLevel(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.level.String()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestConnectivityCheckResult_AddTODO(t *testing.T) {
	result := &ConnectivityCheckResult{
		StartTime: time.Now(),
		TODOs:     []TODO{},
	}

	// Test adding different TODO levels
	result.AddTODOf(TodoInfo, "This is an info message")
	result.AddTODOf(TodoWarn, "This is a warning: %s", "test warning")
	result.AddTODOf(TodoFail, "This is a failure for %s on port %d", "example.com", 443)

	// Verify TODOs were added
	if len(result.TODOs) != 3 {
		t.Errorf("Expected 3 TODOs, got %d", len(result.TODOs))
	}

	// Verify first TODO
	if result.TODOs[0].Level != TodoInfo {
		t.Errorf("Expected first TODO level to be TodoInfo, got %v", result.TODOs[0].Level)
	}
	if result.TODOs[0].Message != "This is an info message" {
		t.Errorf("Expected first TODO message to be 'This is an info message', got %s", result.TODOs[0].Message)
	}

	// Verify second TODO with formatting
	if result.TODOs[1].Level != TodoWarn {
		t.Errorf("Expected second TODO level to be TodoWarn, got %v", result.TODOs[1].Level)
	}
	if result.TODOs[1].Message != "This is a warning: test warning" {
		t.Errorf("Expected second TODO message to be 'This is a warning: test warning', got %s", result.TODOs[1].Message)
	}

	// Verify third TODO with multiple format args
	if result.TODOs[2].Level != TodoFail {
		t.Errorf("Expected third TODO level to be TodoFail, got %v", result.TODOs[2].Level)
	}
	expectedMsg := "This is a failure for example.com on port 443"
	if result.TODOs[2].Message != expectedMsg {
		t.Errorf("Expected third TODO message to be '%s', got %s", expectedMsg, result.TODOs[2].Message)
	}
}

func TestSnykHosts(t *testing.T) {
	// Get hosts using thread-safe getter
	hosts := GetSnykHosts()

	// Verify we have the expected number of hosts
	expectedCount := 16
	if len(hosts) != expectedCount {
		t.Errorf("Expected %d Snyk hosts, got %d", expectedCount, len(hosts))
	}

	// Verify some key hosts are present
	requiredHosts := []string{
		"api.snyk.io",
		"app.snyk.io",
		"api.eu.snyk.io",
		"api.us.snyk.io",
		"api.au.snyk.io",
		"api.snykgov.io",
		"deeproxy.snyk.io/filters",
		"downloads.snyk.io:443/cli/wasm/bundle.tar.gz",
		"sentry.io",
	}

	for _, required := range requiredHosts {
		found := false
		for _, host := range hosts {
			if host == required {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Required host %s not found in SnykHosts", required)
		}
	}
}
