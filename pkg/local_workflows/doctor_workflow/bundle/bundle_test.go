package bundle

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testBundle() *DiagnosticBundle {
	return &DiagnosticBundle{
		Header: "Version:  1.1306.0\nAPI:      https://api.snyk.io",
		Footer: "Exit Code:  2",
		Events: []Event{
			{Line: 6, Kind: "http-error", Message: "< response [0x*]: 401 Unauthorized"},
			{Line: 30, Kind: "http-error", Message: "< response [0x*]: 401 Unauthorized"},
			{Line: 33, Kind: "error", Message: "< error: Authentication error"},
		},
		WhoAmI: Signal{Status: SignalOK, Summary: "jane@corp.io"},
		Connectivity: ConnectivitySummary{
			Proxy:         "none detected",
			HostsOK:       15,
			HostsTotal:    16,
			FailureGroups: []HostFailureGroup{{Status: "TIMEOUT", Hosts: []string{"api.snyk.io"}}},
			TokenPresent:  true,
			OrgCount:      8,
			Organizations: []string{"jane.corp.io (default)", "team-a", "+6 more"},
			Warnings:      []Warning{{Message: "api.snyk.io unreachable, check your firewall", Similar: 15}},
		},
	}
}

func Test_Render_sectionsAndContent(t *testing.T) {
	out := testBundle().Render(false)

	assert.Contains(t, out, "Snyk Doctor Diagnostic Report")
	assert.Contains(t, out, "Environment\n")
	assert.Contains(t, out, "Version:  1.1306.0")
	assert.Contains(t, out, "Result\n")
	assert.Contains(t, out, "Exit Code:  2")
}

func Test_Render_liveChecksAsFindingBlocks(t *testing.T) {
	out := testBundle().Render(false)

	assert.Contains(t, out, " ✓ [OK] Authentication")
	assert.Contains(t, out, "User: jane@corp.io")
	assert.Contains(t, out, " ✗ [FAILED] Connectivity")
	assert.Contains(t, out, "15/16 reachable")
	assert.Contains(t, out, "api.snyk.io: TIMEOUT")
	assert.Contains(t, out, "8 accessible")
	assert.Contains(t, out, "- jane.corp.io (default)")
	assert.Contains(t, out, "- +6 more")
	assert.Contains(t, out, "⚠ api.snyk.io unreachable, check your firewall (+15 similar)")
}

func Test_Render_eventsAsFindingBlocks(t *testing.T) {
	out := testBundle().Render(false)

	assert.Contains(t, out, "3 log entries, 2 distinct")
	assert.Contains(t, out, " ✗ [HTTP-ERROR] < response [0x*]: 401 Unauthorized")
	assert.Contains(t, out, "Occurrences: 2, lines 6-30")
	assert.Contains(t, out, " ✗ [ERROR] < error: Authentication error")
	assert.Contains(t, out, "Occurrences: line 33")
	// the deduped message appears once, not twice
	assert.Equal(t, 1, strings.Count(out, "401 Unauthorized"))
}

func Test_RenderLiveChecks_onlyLiveChecks(t *testing.T) {
	out := testBundle().RenderLiveChecks(false)

	assert.Contains(t, out, "Live Checks")
	assert.Contains(t, out, "User: jane@corp.io")
	assert.NotContains(t, out, "Environment")
	assert.NotContains(t, out, "Exit Code:")
	assert.NotContains(t, out, "401 Unauthorized")
}

func Test_Render_whoamiFailed(t *testing.T) {
	b := testBundle()
	b.WhoAmI = Signal{Status: SignalFailed, Summary: "not authenticated", Detail: "connection refused"}
	out := b.Render(false)

	assert.Contains(t, out, " ✗ [FAILED] Authentication")
	assert.Contains(t, out, "Info: not authenticated")
	assert.Contains(t, out, "Error: connection refused")
}

func Test_Render_connectivityFailedToRun(t *testing.T) {
	b := testBundle()
	b.Connectivity = ConnectivitySummary{Failed: true, FailureText: "context deadline exceeded"}
	out := b.Render(false)

	assert.Contains(t, out, " ✗ [FAILED] Connectivity")
	assert.Contains(t, out, "Error: context deadline exceeded")
}

func Test_Render_failureGroupCoversAllHosts(t *testing.T) {
	b := testBundle()
	b.Connectivity.HostsOK = 0
	b.Connectivity.FailureGroups = []HostFailureGroup{{
		Status: "BLOCKED",
		Hosts: []string{
			"a", "b", "c", "d", "e", "f", "g", "h",
			"i", "j", "k", "l", "m", "n", "o", "p",
		},
	}}
	out := b.Render(false)

	assert.Contains(t, out, "Failed:")
	assert.Contains(t, out, "all 16 endpoints BLOCKED")
	assert.NotContains(t, out, "a, b, c")
}

func Test_Render_wrapsLongWarnings(t *testing.T) {
	b := testBundle()
	b.Connectivity.Warnings = []Warning{{Message: strings.Repeat("firewall issue detected here ", 8)}}
	out := b.Render(false)

	for _, line := range strings.Split(out, "\n") {
		assert.LessOrEqual(t, len(line), 110)
	}
}

func Test_Render_noColorHasNoANSI(t *testing.T) {
	out := testBundle().Render(false)
	assert.NotContains(t, out, "\x1b[")
}

func Test_Render_emptySections(t *testing.T) {
	b := &DiagnosticBundle{
		WhoAmI:       Signal{Status: SignalFailed, Summary: "not authenticated"},
		Connectivity: ConnectivitySummary{},
	}
	out := b.Render(false)

	assert.Contains(t, out, "(not found in the provided log)")
	assert.Contains(t, out, "No failing requests or error/warn entries found")
}
