package connectivity

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Formatter_FormatResult_BasicOutput(t *testing.T) {
	result := &ConnectivityCheckResult{
		HostResults: []HostResult{
			{
				DisplayHost: "api.snyk.io",
				Status:      StatusOK,
				StatusCode:  200,
			},
		},
	}

	buf := &bytes.Buffer{}
	formatter := NewFormatter(buf, false)

	err := formatter.FormatResult(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Testing connectivity to Snyk endpoints")
	assert.Contains(t, output, "api.snyk.io")
	assert.Contains(t, output, "OK")
}

func Test_Formatter_FormatResult_WithProxy(t *testing.T) {
	result := &ConnectivityCheckResult{
		ProxyConfig: ProxyConfig{
			Detected: true,
			URL:      "http://proxy.example.com:8080",
			Variable: "HTTPS_PROXY",
		},
	}

	buf := &bytes.Buffer{}
	formatter := NewFormatter(buf, false)

	err := formatter.FormatResult(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Proxy detected")
	assert.Contains(t, output, "HTTPS_PROXY")
}

func Test_Formatter_FormatResult_WithTODOs(t *testing.T) {
	result := &ConnectivityCheckResult{
		TODOs: []TODO{
			{
				Level:   TodoFail,
				Message: "DNS resolution failed for 'api.snyk.io'",
			},
		},
	}

	buf := &bytes.Buffer{}
	formatter := NewFormatter(buf, false)

	err := formatter.FormatResult(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Actionable TODOs")
	assert.Contains(t, output, "DNS resolution failed")
}

func Test_Formatter_FormatResult_ColorOutputEnabled(t *testing.T) {
	result := &ConnectivityCheckResult{
		HostResults: []HostResult{
			{
				DisplayHost: "api.snyk.io",
				Status:      StatusOK,
				StatusCode:  200,
			},
		},
	}

	buf := &bytes.Buffer{}
	formatter := NewFormatter(buf, true)

	err := formatter.FormatResult(result)
	require.NoError(t, err)

	output := buf.String()
	// When colors are enabled, output should contain ANSI escape codes
	// We just verify that the content is there, not the exact ANSI codes
	assert.Contains(t, output, "api.snyk.io")
}

func Test_Formatter_FormatResult_WithOrganizations(t *testing.T) {
	result := &ConnectivityCheckResult{
		TokenPresent: true,
		Organizations: []Organization{
			{
				ID:        "org-1",
				Name:      "Test Org",
				Slug:      "test-org",
				GroupID:   "group-1",
				IsDefault: true,
			},
		},
	}

	buf := &bytes.Buffer{}
	formatter := NewFormatter(buf, false)

	err := formatter.FormatResult(result)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Snyk Token and Organizations")
	assert.Contains(t, output, "Authentication token is configured")
	assert.Contains(t, output, "Found 1 organizations")
	assert.Contains(t, output, "Test Org")
}
