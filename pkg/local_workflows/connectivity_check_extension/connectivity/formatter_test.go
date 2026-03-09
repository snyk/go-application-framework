package connectivity

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var ansiEscapePattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// === Sections ===

type formatterOutputSection int

const (
	sectionUnknown formatterOutputSection = iota
	sectionProxyConfig
	sectionHostResults
	sectionTODOs
	sectionOrganizations
)

var startingLineToSection = map[string]formatterOutputSection{
	"Checking for proxy configuration...":       sectionProxyConfig,
	"Testing connectivity to Snyk endpoints...": sectionHostResults,
	"Actionable TODOs":                          sectionTODOs,
	"Snyk Token and Organizations":              sectionOrganizations,
}

var sectionLabels = map[formatterOutputSection]string{
	sectionProxyConfig:   "Proxy Configuration",
	sectionHostResults:   "Host Results",
	sectionTODOs:         "Actionable TODOs",
	sectionOrganizations: "Organization Details",
}

func sectionLabel(section formatterOutputSection) string {
	if label, ok := sectionLabels[section]; ok {
		return label
	}
	return "[Unknown Section]"
}

// === Parsing ===

type parsedOrgRow struct {
	GroupID   string
	OrgID     string
	Name      string
	Slug      string
	IsDefault bool
}

type parsedFormatterOutput struct {
	sectionLines map[formatterOutputSection][]string
	envResults   map[string]string
	hostResults  map[string]string
	orgResults   []parsedOrgRow
}

func (o parsedFormatterOutput) assertDoesNotContainSubstring(t *testing.T, substring string) {
	t.Helper()
	for section := range o.sectionLines {
		for _, line := range o.sectionLines[section] {
			if strings.Contains(line, substring) {
				assert.Fail(t, "Output contains substring", "Unexpectedly found: '%s', within line: '%s', within section: '%s'", substring, line, sectionLabel(section))
			}
		}
	}
}

func parseFormatterOutput(t *testing.T, buf *bytes.Buffer, expectOrgSection bool) parsedFormatterOutput {
	t.Helper()

	sectionLines := processOutputIntoSections(t, buf, expectOrgSection)

	parsed := parsedFormatterOutput{
		sectionLines: sectionLines,
		envResults:   parseEnvVars(t, sectionLines[sectionProxyConfig]),
		hostResults:  parseHostResults(t, sectionLines[sectionHostResults]),
	}

	if expectOrgSection {
		parsed.orgResults = parseOrgRows(sectionLines[sectionOrganizations])
	}

	return parsed
}

func processOutputIntoSections(t *testing.T, buf *bytes.Buffer, expectOrgSection bool) map[formatterOutputSection][]string {
	t.Helper()

	scanner := bufio.NewScanner(bytes.NewReader(buf.Bytes()))
	currentSection := sectionUnknown
	sectionLines := make(map[formatterOutputSection][]string)

	for scanner.Scan() {
		// Normalize line.
		rawLine := scanner.Text()
		lineWithoutANSI := ansiEscapePattern.ReplaceAllString(rawLine, "")
		normalizedLine := strings.Join(strings.Fields(strings.TrimSpace(lineWithoutANSI)), " ")
		if normalizedLine == "" {
			continue
		}

		if nextSection, ok := startingLineToSection[normalizedLine]; ok {
			// Line is section heading.
			if currentSection+1 != nextSection {
				require.FailNowf(t,
					"Formatter outputted sections in the wrong order",
					"Got '%s' when expected '%s' following '%s'",
					sectionLabel(nextSection),
					sectionLabel(currentSection+1),
					sectionLabel(currentSection),
				)
			}
			currentSection = nextSection
		} else {
			// Regular line.
			if currentSection == sectionUnknown {
				require.FailNow(t, "Unexpected lines when should have expected the first section.")
			}
			sectionLines[currentSection] = append(sectionLines[currentSection], normalizedLine)
		}
	}

	// Assert processing was as expected.
	require.NoError(t, scanner.Err())
	expectedLastSection := utils.Ternary(expectOrgSection, sectionOrganizations, sectionTODOs)
	require.Equal(t, sectionLabel(expectedLastSection), sectionLabel(currentSection), "Unexpected last section.")

	return sectionLines
}

func parseEnvVars(t *testing.T, lines []string) map[string]string {
	t.Helper()
	envVars := make(map[string]string)
	for _, line := range lines {
		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:colonIdx])
		val := strings.TrimSpace(line[colonIdx+1:])
		if key == "" || key == "Environment variables" {
			continue
		}

		require.NotContains(t, envVars, key, "Duplicate environment variable key in output")
		envVars[key] = val
	}
	return envVars
}

func parseHostResults(t *testing.T, lines []string) map[string]string {
	t.Helper()
	results := make(map[string]string)
	for _, normalized := range lines {
		if strings.Contains(normalized, "---") || strings.Contains(normalized, "──") {
			continue
		}

		fields := strings.Fields(normalized)
		if len(fields) < 2 {
			continue
		}

		host := fields[0]
		if host == "" || host == "Host" {
			continue
		}

		require.NotContains(t, results, host, "Duplicate host key in output")
		results[host] = strings.Join(fields[1:], " ")
	}
	return results
}

func parseOrgRows(lines []string) []parsedOrgRow {
	var rows []parsedOrgRow
	for _, line := range lines {
		if strings.Contains(line, "---") || strings.Contains(line, "──") {
			continue
		}
		fields := strings.Fields(line)

		// Skip non-data lines: headers, status messages, counts
		if len(fields) < 4 {
			continue
		}
		if fields[0] == "Group" || fields[0] == "✓" || fields[0] == "✗" || fields[0] == "Found" || fields[0] == "No" || fields[0] == "Configure" {
			continue
		}

		row := parsedOrgRow{
			GroupID: fields[0],
			OrgID:   fields[1],
			Name:    fields[2],
			Slug:    fields[3],
		}
		if len(fields) >= 5 && fields[4] == "Yes" {
			row.IsDefault = true
		}
		rows = append(rows, row)
	}
	return rows
}

// === Tests ===

func Test_Formatter_FormatResult(t *testing.T) {
	formatterTestCases := []struct {
		name             string
		setEnvVars       map[string]string
		result           *ConnectivityCheckResult
		useColor         bool
		expectOrgSection bool
		assertions       func(t *testing.T, parsed parsedFormatterOutput)
	}{
		// --- Proxy tests ---
		{
			name: "proxy detected and env var displayed when set",
			setEnvVars: map[string]string{
				"HTTPS_PROXY": "http://proxy.example.com:8080",
			},
			result: &ConnectivityCheckResult{
				ProxyConfig: ProxyConfig{
					Detected: true,
					URL:      "http://proxy.example.com:8080",
					Variable: "HTTPS_PROXY",
				},
			},
			assertions: func(t *testing.T, parsed parsedFormatterOutput) {
				t.Helper()
				if assert.Contains(t, parsed.envResults, "HTTPS_PROXY") {
					assert.Equal(t, "http://proxy.example.com:8080", parsed.envResults["HTTPS_PROXY"])
				}
				assert.Contains(t, parsed.sectionLines[sectionProxyConfig], "✓ Proxy detected via HTTPS_PROXY: http://proxy.example.com:8080")
				assert.Contains(t, parsed.sectionLines[sectionProxyConfig], "Testing connectivity through proxy...")

				parsed.assertDoesNotContainSubstring(t, "No proxy detected")
				parsed.assertDoesNotContainSubstring(t, "Testing direct connection...")
			},
		},
		{
			name: "no proxy detected",
			result: &ConnectivityCheckResult{
				ProxyConfig: ProxyConfig{Detected: false},
			},
			assertions: func(t *testing.T, parsed parsedFormatterOutput) {
				t.Helper()
				assert.Contains(t, parsed.sectionLines[sectionProxyConfig],
					"ℹ No proxy detected - Testing direct connection...")

				parsed.assertDoesNotContainSubstring(t, "Proxy detected via")
			},
		},

		// --- Host result status tests ---
		{
			name: "host StatusOK",
			result: &ConnectivityCheckResult{
				HostResults: []HostResult{
					{
						DisplayHost: "api.snyk.io",
						Status:      StatusOK,
						StatusCode:  200,
					},
				},
			},
			assertions: func(t *testing.T, parsed parsedFormatterOutput) {
				t.Helper()
				require.Contains(t, parsed.hostResults, "api.snyk.io")
				assert.Equal(t, "OK (HTTP 200)", parsed.hostResults["api.snyk.io"])

				assert.NotContains(t, parsed.hostResults, "api.eu.snyk.io")
			},
		},
		{
			name: "host StatusProxyAuthSupported",
			result: &ConnectivityCheckResult{
				HostResults: []HostResult{
					{
						DisplayHost: "api.snyk.io",
						Status:      StatusProxyAuthSupported,
						StatusCode:  407,
					},
				},
			},
			assertions: func(t *testing.T, parsed parsedFormatterOutput) {
				t.Helper()
				require.Contains(t, parsed.hostResults, "api.snyk.io")
				assert.Equal(t, "PROXY AUTH REQUIRED (SUPPORTED) (HTTP 407)", parsed.hostResults["api.snyk.io"])
			},
		},
		{
			name: "host StatusReachable warning",
			result: &ConnectivityCheckResult{
				HostResults: []HostResult{
					{
						DisplayHost: "app.snyk.io",
						Status:      StatusReachable,
						StatusCode:  301,
					},
				},
			},
			assertions: func(t *testing.T, parsed parsedFormatterOutput) {
				t.Helper()
				require.Contains(t, parsed.hostResults, "app.snyk.io")
				assert.Equal(t, "REACHABLE (HTTP 301)", parsed.hostResults["app.snyk.io"])
			},
		},
		{
			name: "host StatusDNSError with error message",
			result: &ConnectivityCheckResult{
				HostResults: []HostResult{
					{
						DisplayHost: "api.snyk.io",
						Status:      StatusDNSError,
						Error:       fmt.Errorf("lookup api.snyk.io: no such host"),
					},
				},
			},
			assertions: func(t *testing.T, parsed parsedFormatterOutput) {
				t.Helper()
				require.Contains(t, parsed.hostResults, "api.snyk.io")
				assert.Equal(t, "DNS ERROR - lookup api.snyk.io: no such host", parsed.hostResults["api.snyk.io"])
			},
		},
		{
			name: "host StatusTimeout without HTTP code",
			result: &ConnectivityCheckResult{
				HostResults: []HostResult{
					{
						DisplayHost: "api.snyk.io",
						Status:      StatusTimeout,
						StatusCode:  0,
					},
				},
			},
			assertions: func(t *testing.T, parsed parsedFormatterOutput) {
				t.Helper()
				require.Contains(t, parsed.hostResults, "api.snyk.io")
				assert.Equal(t, "TIMEOUT", parsed.hostResults["api.snyk.io"])
			},
		},

		// --- TODO tests ---
		{
			name: "empty TODOs shows all checks passed",
			result: &ConnectivityCheckResult{
				TODOs: []TODO{},
			},
			assertions: func(t *testing.T, parsed parsedFormatterOutput) {
				t.Helper()
				assert.Contains(t, parsed.sectionLines[sectionTODOs],
					"All checks passed. Your network configuration appears to be compatible with Snyk CLI.")

				parsed.assertDoesNotContainSubstring(t, "FAIL:")
			},
		},
		{
			name: "TODOs with fail level",
			result: &ConnectivityCheckResult{
				TODOs: []TODO{
					{
						Level:   TodoFail,
						Message: "DNS resolution failed for 'api.snyk.io'",
					},
				},
			},
			assertions: func(t *testing.T, parsed parsedFormatterOutput) {
				t.Helper()
				assert.Contains(t, parsed.sectionLines[sectionTODOs], "FAIL: DNS resolution failed for 'api.snyk.io'")

				parsed.assertDoesNotContainSubstring(t, "All checks passed.")
				parsed.assertDoesNotContainSubstring(t, "Your network configuration appears to be compatible with Snyk CLI.")
			},
		},
		{
			name: "duplicate TODOs are deduplicated",
			result: &ConnectivityCheckResult{
				TODOs: []TODO{
					{Level: TodoFail, Message: "DNS failed"},
					{Level: TodoFail, Message: "DNS failed"},
					{Level: TodoWarn, Message: "Slow response"},
				},
			},
			assertions: func(t *testing.T, parsed parsedFormatterOutput) {
				t.Helper()
				failCount := 0
				for _, line := range parsed.sectionLines[sectionTODOs] {
					if strings.Contains(line, "FAIL: DNS failed") {
						failCount++
					}
				}
				assert.Equal(t, 1, failCount, "duplicate TODO should appear only once")
				assert.Contains(t, parsed.sectionLines[sectionTODOs], "WARN: Slow response")
			},
		},
		{
			name: "all three TODO levels",
			result: &ConnectivityCheckResult{
				TODOs: []TODO{
					{Level: TodoInfo, Message: "informational note"},
					{Level: TodoWarn, Message: "warning note"},
					{Level: TodoFail, Message: "failure note"},
				},
			},
			assertions: func(t *testing.T, parsed parsedFormatterOutput) {
				t.Helper()
				assert.Contains(t, parsed.sectionLines[sectionTODOs], "INFO: informational note")
				assert.Contains(t, parsed.sectionLines[sectionTODOs], "WARN: warning note")
				assert.Contains(t, parsed.sectionLines[sectionTODOs], "FAIL: failure note")

				parsed.assertDoesNotContainSubstring(t, "All checks passed.")
				parsed.assertDoesNotContainSubstring(t, "Your network configuration appears to be compatible with Snyk CLI.")
			},
		},

		// --- Organization tests ---
		{
			name: "no token skips org section",
			result: &ConnectivityCheckResult{
				TokenPresent:  false,
				OrgCheckError: nil,
			},
			assertions: func(t *testing.T, parsed parsedFormatterOutput) {
				t.Helper()
				assert.NotContains(t, parsed.sectionLines, sectionOrganizations) // Just to double check.

				parsed.assertDoesNotContainSubstring(t, "Authentication token is configured")
			},
		},
		{
			name: "token present with default org",
			result: &ConnectivityCheckResult{
				TokenPresent: true,
				Organizations: []Organization{
					{
						ID:        "org-1",
						Name:      "TestOrg",
						Slug:      "test-org",
						GroupID:   "group-1",
						IsDefault: true,
					},
				},
			},
			expectOrgSection: true,
			assertions: func(t *testing.T, parsed parsedFormatterOutput) {
				t.Helper()
				assert.Contains(t, parsed.sectionLines[sectionOrganizations], "✓ Authentication token is configured")
				assert.Contains(t, parsed.sectionLines[sectionOrganizations], "Found 1 organizations:")

				parsed.assertDoesNotContainSubstring(t, "No organizations found")

				require.Len(t, parsed.orgResults, 1)
				assert.Equal(t, "group-1", parsed.orgResults[0].GroupID)
				assert.Equal(t, "org-1", parsed.orgResults[0].OrgID)
				assert.Equal(t, "TestOrg", parsed.orgResults[0].Name)
				assert.Equal(t, "test-org", parsed.orgResults[0].Slug)
				assert.True(t, parsed.orgResults[0].IsDefault)
			},
		},
		{
			name: "token present but org fetch error",
			result: &ConnectivityCheckResult{
				TokenPresent:  true,
				OrgCheckError: fmt.Errorf("401 Unauthorized"),
			},
			expectOrgSection: true,
			assertions: func(t *testing.T, parsed parsedFormatterOutput) {
				t.Helper()
				assert.Contains(t, parsed.sectionLines[sectionOrganizations], "✓ Authentication token is configured")
				assert.Contains(t, parsed.sectionLines[sectionOrganizations], "✗ Failed to fetch organizations: 401 Unauthorized")

				parsed.assertDoesNotContainSubstring(t, "Found 1 organizations:")
			},
		},
		{
			name: "token present but empty organizations",
			result: &ConnectivityCheckResult{
				TokenPresent:  true,
				Organizations: []Organization{},
			},
			expectOrgSection: true,
			assertions: func(t *testing.T, parsed parsedFormatterOutput) {
				t.Helper()
				assert.Contains(t, parsed.sectionLines[sectionOrganizations], "✓ Authentication token is configured")
				assert.Contains(t, parsed.sectionLines[sectionOrganizations], "No organizations found")

				parsed.assertDoesNotContainSubstring(t, "Found 1 organizations:")
			},
		},
		{
			name: "multiple orgs mixed default and non-default",
			result: &ConnectivityCheckResult{
				TokenPresent: true,
				Organizations: []Organization{
					{ID: "org-1", Name: "DefaultOrg", Slug: "default-org", GroupID: "grp-1", IsDefault: true},
					{ID: "org-2", Name: "OtherOrg", Slug: "other-org", GroupID: "grp-2", IsDefault: false},
				},
			},
			expectOrgSection: true,
			assertions: func(t *testing.T, parsed parsedFormatterOutput) {
				t.Helper()
				assert.Contains(t, parsed.sectionLines[sectionOrganizations], "Found 2 organizations:")

				parsed.assertDoesNotContainSubstring(t, "No organizations found")

				require.Len(t, parsed.orgResults, 2)

				assert.Equal(t, "org-1", parsed.orgResults[0].OrgID)
				assert.Equal(t, "DefaultOrg", parsed.orgResults[0].Name)
				assert.True(t, parsed.orgResults[0].IsDefault)

				assert.Equal(t, "org-2", parsed.orgResults[1].OrgID)
				assert.Equal(t, "OtherOrg", parsed.orgResults[1].Name)
				assert.False(t, parsed.orgResults[1].IsDefault)
			},
		},

		// --- Color output test ---
		{
			name: "color output produces parseable content across all sections",
			setEnvVars: map[string]string{
				"HTTP_PROXY":  "http://proxy:8080",
				"KRB5_CONFIG": "/etc/krb5.conf",
				"KRB5CCNAME":  "/tmp/krb5cc_1000",
			},
			result: &ConnectivityCheckResult{
				ProxyConfig: ProxyConfig{
					Detected: true,
					URL:      "http://proxy:8080",
					Variable: "HTTP_PROXY",
				},
				HostResults: []HostResult{
					{DisplayHost: "api.snyk.io", Status: StatusOK, StatusCode: 200},
					{DisplayHost: "app.snyk.io", Status: StatusReachable, StatusCode: 301},
				},
				TODOs: []TODO{
					{Level: TodoWarn, Message: "reachable but unexpected status"},
				},
				TokenPresent: true,
				Organizations: []Organization{
					{ID: "org-1", Name: "ColorOrg", Slug: "color-org", GroupID: "grp-1", IsDefault: true},
				},
			},
			useColor:         true,
			expectOrgSection: true,
			assertions: func(t *testing.T, parsed parsedFormatterOutput) {
				t.Helper()
				// Proxy section.
				assert.Contains(t, parsed.sectionLines[sectionProxyConfig],
					"✓ Proxy detected via HTTP_PROXY: http://proxy:8080")
				assert.Contains(t, parsed.sectionLines[sectionProxyConfig],
					"Testing connectivity through proxy...")

				// Env vars.
				if assert.Contains(t, parsed.envResults, "HTTP_PROXY") {
					assert.Equal(t, "http://proxy:8080", parsed.envResults["HTTP_PROXY"])
				}
				if assert.Contains(t, parsed.envResults, "KRB5_CONFIG") {
					assert.Equal(t, "/etc/krb5.conf", parsed.envResults["KRB5_CONFIG"])
				}
				if assert.Contains(t, parsed.envResults, "KRB5CCNAME") {
					assert.Equal(t, "/tmp/krb5cc_1000", parsed.envResults["KRB5CCNAME"])
				}

				// Host results.
				if assert.Contains(t, parsed.hostResults, "api.snyk.io") {
					assert.Equal(t, "OK (HTTP 200)", parsed.hostResults["api.snyk.io"])
				}
				if assert.Contains(t, parsed.hostResults, "app.snyk.io") {
					assert.Equal(t, "REACHABLE (HTTP 301)", parsed.hostResults["app.snyk.io"])
				}

				// TODOs.
				assert.Contains(t, parsed.sectionLines[sectionTODOs],
					"WARN: reachable but unexpected status")

				// Organizations.
				assert.Contains(t, parsed.sectionLines[sectionOrganizations],
					"✓ Authentication token is configured")
				require.Len(t, parsed.orgResults, 1)
				assert.Equal(t, "ColorOrg", parsed.orgResults[0].Name)
				assert.True(t, parsed.orgResults[0].IsDefault)
			},
		},
	}
	for _, tc := range formatterTestCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup.
			if tc.setEnvVars != nil {
				for key, value := range tc.setEnvVars {
					t.Setenv(key, value)
				}
			}
			buf := &bytes.Buffer{}
			formatter := NewFormatter(buf, tc.useColor)

			// Act.
			err := formatter.FormatResult(tc.result)
			require.NoError(t, err)

			// Verify.
			parsed := parseFormatterOutput(t, buf, tc.expectOrgSection)
			if tc.assertions != nil {
				tc.assertions(t, parsed)
			}
		})
	}
}
