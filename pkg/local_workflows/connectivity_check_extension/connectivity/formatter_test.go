package connectivity

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestNewFormatter(t *testing.T) {
	var buf bytes.Buffer

	// Test with color enabled
	formatter := NewFormatter(&buf, true)
	if formatter.useColor != true {
		t.Error("Expected useColor to be true")
	}
	if formatter.writer != &buf {
		t.Error("Expected writer to be set correctly")
	}

	// Test with color disabled
	formatter = NewFormatter(&buf, false)
	if formatter.useColor != false {
		t.Error("Expected useColor to be false")
	}
}

func TestFormatter_colorize(t *testing.T) {
	var buf bytes.Buffer

	// Test with color enabled
	formatter := NewFormatter(&buf, true)
	result := formatter.colorize(ColorGreen, "test")
	expected := ColorGreen + "test" + ColorReset
	if result != expected {
		t.Errorf("Expected '%s', got '%s'", expected, result)
	}

	// Test with color disabled
	formatter = NewFormatter(&buf, false)
	result = formatter.colorize(ColorGreen, "test")
	if result != "test" {
		t.Errorf("Expected 'test' without color, got '%s'", result)
	}
}

func TestFormatter_formatHostResult(t *testing.T) {
	tests := []struct {
		name        string
		result      HostResult
		useColor    bool
		contains    []string
		notContains []string
	}{
		{
			name: "OK status",
			result: HostResult{
				DisplayHost: "api.snyk.io",
				Status:      StatusOK,
				StatusCode:  200,
			},
			useColor: false,
			contains: []string{"api.snyk.io", "OK (HTTP 200)"},
		},
		{
			name: "Reachable status",
			result: HostResult{
				DisplayHost: "static.snyk.io",
				Status:      StatusReachable,
				StatusCode:  403,
			},
			useColor: false,
			contains: []string{"static.snyk.io", "REACHABLE (HTTP 403)"},
		},
		{
			name: "DNS Error",
			result: HostResult{
				DisplayHost: "bad.example.com",
				Status:      StatusDNSError,
				Error:       &mockError{msg: "no such host"},
			},
			useColor: false,
			contains: []string{"bad.example.com", "DNS ERROR", "no such host"},
		},
		{
			name: "Proxy Auth Supported",
			result: HostResult{
				DisplayHost: "api.snyk.io",
				Status:      StatusProxyAuthSupported,
				StatusCode:  407,
			},
			useColor: false,
			contains: []string{"api.snyk.io", "PROXY AUTH REQUIRED (SUPPORTED) (HTTP 407)"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			formatter := NewFormatter(&buf, tt.useColor)

			err := formatter.formatHostResult(tt.result)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			output := buf.String()

			// Check expected strings are present
			for _, expected := range tt.contains {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output to contain '%s', got: %s", expected, output)
				}
			}

			// Check unexpected strings are not present
			for _, unexpected := range tt.notContains {
				if strings.Contains(output, unexpected) {
					t.Errorf("Expected output not to contain '%s', got: %s", unexpected, output)
				}
			}
		})
	}
}

func TestFormatter_formatProxyConfig(t *testing.T) {
	tests := []struct {
		name     string
		config   ProxyConfig
		envVars  map[string]string
		contains []string
	}{
		{
			name: "Proxy detected",
			config: ProxyConfig{
				Detected: true,
				URL:      "http://proxy.example.com:8080",
				Variable: "HTTPS_PROXY",
			},
			envVars: map[string]string{
				"HTTPS_PROXY": "http://proxy.example.com:8080",
			},
			contains: []string{
				"Proxy detected",
				"HTTPS_PROXY",
				"http://proxy.example.com:8080",
				"Testing connectivity through proxy",
			},
		},
		{
			name: "No proxy detected",
			config: ProxyConfig{
				Detected: false,
			},
			envVars: map[string]string{},
			contains: []string{
				"No proxy detected",
				"Testing direct connection",
				"(not set)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variables using t.Setenv
			// Clear relevant proxy variables first
			t.Setenv("HTTPS_PROXY", "")
			t.Setenv("https_proxy", "")
			t.Setenv("HTTP_PROXY", "")
			t.Setenv("http_proxy", "")
			t.Setenv("NO_PROXY", "")
			t.Setenv("no_proxy", "")

			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			var buf bytes.Buffer
			formatter := NewFormatter(&buf, false)

			err := formatter.formatProxyConfig(tt.config)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			output := buf.String()

			for _, expected := range tt.contains {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output to contain '%s', got: %s", expected, output)
				}
			}
		})
	}
}

func TestFormatter_formatTODOs(t *testing.T) {
	tests := []struct {
		name     string
		todos    []TODO
		contains []string
	}{
		{
			name:  "No TODOs",
			todos: []TODO{},
			contains: []string{
				"Actionable TODOs",
				"All checks passed",
				"compatible with Snyk CLI",
			},
		},
		{
			name: "Mixed TODOs",
			todos: []TODO{
				{Level: TodoInfo, Message: "Info message"},
				{Level: TodoWarn, Message: "Warning message"},
				{Level: TodoFail, Message: "Failure message"},
			},
			contains: []string{
				"Actionable TODOs",
				"INFO: Info message",
				"WARN: Warning message",
				"FAIL: Failure message",
			},
		},
		{
			name: "Duplicate TODOs removed",
			todos: []TODO{
				{Level: TodoWarn, Message: "Same warning"},
				{Level: TodoWarn, Message: "Same warning"},
				{Level: TodoFail, Message: "Same failure"},
				{Level: TodoFail, Message: "Same failure"},
			},
			contains: []string{
				"WARN: Same warning",
				"FAIL: Same failure",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			formatter := NewFormatter(&buf, false)

			err := formatter.formatTODOs(tt.todos)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			output := buf.String()

			for _, expected := range tt.contains {
				if !strings.Contains(output, expected) {
					t.Errorf("Expected output to contain '%s', got: %s", expected, output)
				}
			}

			// For duplicate test, verify count
			if tt.name == "Duplicate TODOs removed" {
				warnCount := strings.Count(output, "WARN: Same warning")
				failCount := strings.Count(output, "FAIL: Same failure")
				if warnCount != 1 {
					t.Errorf("Expected 1 warning, got %d", warnCount)
				}
				if failCount != 1 {
					t.Errorf("Expected 1 failure, got %d", failCount)
				}
			}
		})
	}
}

func TestFormatter_FormatResult(t *testing.T) {
	// Create a complete result
	result := &ConnectivityCheckResult{
		StartTime: time.Now(),
		EndTime:   time.Now(),
		ProxyConfig: ProxyConfig{
			Detected: false,
		},
		HostResults: []HostResult{
			{
				DisplayHost: "api.snyk.io",
				Status:      StatusOK,
				StatusCode:  204,
			},
			{
				DisplayHost: "app.snyk.io",
				Status:      StatusOK,
				StatusCode:  200,
			},
		},
		TODOs: []TODO{},
	}

	var buf bytes.Buffer
	formatter := NewFormatter(&buf, false)

	err := formatter.FormatResult(result)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	output := buf.String()

	// Verify all major sections are present
	expectedSections := []string{
		"Checking for proxy configuration",
		"Environment variables:",
		"Host",
		"Result",
		"api.snyk.io",
		"OK (HTTP 204)",
		"app.snyk.io",
		"OK (HTTP 200)",
		"Actionable TODOs",
		"All checks passed",
		"NODE_EXTRA_CA_CERTS",
	}

	for _, expected := range expectedSections {
		if !strings.Contains(output, expected) {
			t.Errorf("Expected output to contain '%s'", expected)
		}
	}
}

func TestDeduplicateTODOs(t *testing.T) {
	todos := []TODO{
		{Level: TodoInfo, Message: "Message 1"},
		{Level: TodoInfo, Message: "Message 1"}, // Duplicate
		{Level: TodoWarn, Message: "Message 2"},
		{Level: TodoInfo, Message: "Message 3"},
		{Level: TodoWarn, Message: "Message 2"}, // Duplicate
	}

	unique := deduplicateTODOs(todos)

	if len(unique) != 3 {
		t.Errorf("Expected 3 unique TODOs, got %d", len(unique))
	}

	// Verify the unique messages
	messages := make(map[string]bool)
	for _, todo := range unique {
		key := todo.Level.String() + ": " + todo.Message
		if messages[key] {
			t.Errorf("Found duplicate TODO: %s", key)
		}
		messages[key] = true
	}
}
