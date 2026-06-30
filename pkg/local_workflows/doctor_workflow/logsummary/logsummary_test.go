package logsummary

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- helpers ---

func summarizeFixture(t *testing.T, name string) Summary {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return Summarize(string(raw))
}

func highlightMessages(highlights []Highlight) string {
	var sb strings.Builder
	for _, h := range highlights {
		sb.WriteString(h.Message)
		sb.WriteString("\n")
	}
	return sb.String()
}

// =============================================================================
// Existing colleague tests (ported to new Summary struct)
// =============================================================================

func Test_Summarize_emptyConfigFixture(t *testing.T) {
	result := summarizeFixture(t, "empty-config.logs")

	assert.Contains(t, result.Header, "Version:")
	assert.Contains(t, result.Header, "API:")
	assert.Contains(t, result.Header, "Checks:")
	assert.NotContains(t, result.Header, "2026-06-18T13:17:15Z main -")

	assert.Contains(t, result.Footer, "Exit Code:")
	assert.Contains(t, result.Footer, "Authentication error (SNYK-0005)")
	assert.NotContains(t, result.Footer, "Platform:")

	require.NotEmpty(t, result.Highlights)
	messages := highlightMessages(result.Highlights)
	assert.Contains(t, messages, "401 Unauthorized")
	assert.Contains(t, messages, "< error:")

	hasHTTPError := false
	for _, h := range result.Highlights {
		if h.Kind == EventHTTPError {
			hasHTTPError = true
		}
		assert.Positive(t, h.Line)
		assert.NotContains(t, h.Message, "Platform:")
	}
	assert.True(t, hasHTTPError)
}

func Test_Summarize_wrongEnvironmentFixture(t *testing.T) {
	result := summarizeFixture(t, "wrong-environment.logs")

	assert.Contains(t, result.Header, "Version:")
	assert.Contains(t, result.Header, "tok11111")
	assert.Contains(t, result.Footer, "Exit Code:")
	assert.NotContains(t, result.Footer, "Platform:")

	assert.Contains(t, highlightMessages(result.Highlights), "401 Unauthorized")
}

func Test_Summarize_noHeaderFooter(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Using log level: debug",
		"2026-06-10T13:10:38Z main - < response [0x2b3cd0a17cc0]: 500 Internal Server Error",
		"2026-06-10T13:10:38Z main - < error: something broke",
	}, "\n")

	result := Summarize(log)

	assert.Empty(t, result.Header)
	assert.Empty(t, result.Footer)
	require.Len(t, result.Highlights, 2)
	assert.Equal(t, EventHTTPError, result.Highlights[0].Kind)
	assert.Equal(t, 2, result.Highlights[0].Line)
	assert.Equal(t, EventError, result.Highlights[1].Kind)
}

func Test_Summarize_successfulResponsesNotHighlighted(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - < response [0x2b3cd0a17cc0]: 200 OK",
		"2026-06-10T13:10:38Z main - < response [0x2b3cd0a17cc0]: 304 Not Modified",
	}, "\n")

	assert.Empty(t, Summarize(log).Highlights)
}

func Test_Summarize_highlightCap(t *testing.T) {
	var b strings.Builder
	for i := range maxHighlights + 50 {
		fmt.Fprintf(&b, "2026-06-10T13:10:38Z main - < error: failure %d\n", i)
	}

	result := Summarize(b.String())

	assert.Len(t, result.Highlights, maxHighlights)
	assert.True(t, result.Truncated)
	assert.Contains(t, result.Format(), "remaining log not scanned")
}

func Test_Summarize_dedupesRepeatedEvents(t *testing.T) {
	line := "2026-06-10T13:10:38Z main - < response [0x2b3cd0a17cc0]: 401 Unauthorized\n"
	result := Summarize(strings.Repeat(line, 10))

	require.Len(t, result.Highlights, 1)
	assert.Equal(t, EventHTTPError, result.Highlights[0].Kind)
	assert.Equal(t, 1, result.Highlights[0].Line)
	assert.Equal(t, "< response [0x2b3cd0a17cc0]: 401 Unauthorized", result.Highlights[0].Message)
}

func Test_Summarize_unknownHeaderField(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Version:               1.0.0",
		"2026-06-10T13:10:38Z main - Some New Field:        a value",
		"2026-06-10T13:10:38Z main - > request [0x2b3cd0a17cc0]: GET https://api.snyk.io",
	}, "\n")

	assert.Contains(t, Summarize(log).Header, "Some New Field:")
}

func Test_Summarize_eventAfterHeaderNotSwallowed(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Version:               1.0.0",
		"2026-06-10T13:10:38Z main - Platform:              darwin arm64",
		"2026-06-10T13:10:38Z main - Failed to fetch organizations: auth failed",
	}, "\n")

	result := Summarize(log)

	assert.Contains(t, result.Header, "Platform:")
	assert.NotContains(t, result.Header, "Failed to fetch")
	require.Len(t, result.Highlights, 1)
	assert.Equal(t, EventError, result.Highlights[0].Kind)
}

func Test_Summarize_summaryBlockNotScanned(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - < error: real failure",
		"2026-06-10T13:10:38Z main - ------------ Summary ------------",
		"2026-06-10T13:10:38Z main - < error: reprinted noise",
		"2026-06-10T13:10:38Z main - ------------ Errors ------------",
		"2026-06-10T13:10:38Z main - ERROR:                 Auth error (SNYK-0005)",
		"2026-06-10T13:10:38Z main - Exit Code:             2",
	}, "\n")

	result := Summarize(log)

	require.Len(t, result.Highlights, 1)
	assert.Equal(t, 1, result.Highlights[0].Line)
	assert.Contains(t, result.Footer, "Auth error (SNYK-0005)")
}

func Test_Summarize_unprefixedMarkersStillDelimitResult(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - < error: real failure",
		"------------ Summary ------------",
		"Version:               1.0.0",
		"------------ Errors ------------",
		"ERROR:                 Auth error (SNYK-0005)",
		"Exit Code:             2",
	}, "\n")

	result := Summarize(log)

	require.Len(t, result.Highlights, 1)
	assert.Equal(t, "< error: real failure", result.Highlights[0].Message)
	assert.Contains(t, result.Footer, "Auth error (SNYK-0005)")
	assert.NotContains(t, result.Footer, "Version:")
}

func Test_Summarize_exitCodeWithoutSummaryIsResult(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - < error: real failure",
		"2026-06-10T13:10:38Z main - Exit Code:             2",
	}, "\n")

	result := Summarize(log)

	require.Len(t, result.Highlights, 1)
	assert.Equal(t, "< error: real failure", result.Highlights[0].Message)
	assert.Contains(t, result.Footer, "Exit Code:")
}

func Test_Summarize_responseRequiresStatusLineShape(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - sending response to: 404 handler",
		"2026-06-10T13:10:38Z main - < response [0xbbb]: 503 Service Unavailable",
	}, "\n")

	result := Summarize(log)

	require.Len(t, result.Highlights, 1)
	assert.Equal(t, EventHTTPError, result.Highlights[0].Kind)
	assert.Equal(t, "< response [0xbbb]: 503 Service Unavailable", result.Highlights[0].Message)
}

func Test_Summary_Format(t *testing.T) {
	summary := Summary{
		Header:     "Version: 1.0.0",
		Highlights: []Highlight{{Line: 3, Kind: EventHTTPError, Message: "< response [0x2b3cd0a17cc0]: 401 Unauthorized"}},
		Footer:     "Exit Code: 2",
	}

	rendered := summary.Format()

	assert.Contains(t, rendered, "Snyk Doctor Diagnostic Report")
	assert.Contains(t, rendered, "Environment")
	assert.Contains(t, rendered, "Notable Events")
	assert.Contains(t, rendered, "L3 [http-error]")
	assert.Contains(t, rendered, "401 Unauthorized")
	assert.Contains(t, rendered, "Result")
	assert.Contains(t, rendered, "Exit Code: 2")
}

// =============================================================================
// Phase 0: Edge-case tests
// =============================================================================

func Test_Summarize_emptyLog(t *testing.T) {
	result := Summarize("")
	assert.Empty(t, result.Header)
	assert.Empty(t, result.Footer)
	assert.Empty(t, result.Highlights)
	assert.False(t, result.Truncated)
}

func Test_Summarize_blankLines(t *testing.T) {
	result := Summarize("\n\n   \n\t\n")
	assert.Empty(t, result.Header)
	assert.Empty(t, result.Footer)
	assert.Empty(t, result.Highlights)
}

func Test_Summarize_headerOnlyNothingElse(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Version:               1.0.0",
		"2026-06-10T13:10:38Z main - Platform:              darwin arm64",
		"2026-06-10T13:10:38Z main - API:                   https://api.snyk.io",
	}, "\n")

	result := Summarize(log)

	assert.Contains(t, result.Header, "Version:")
	assert.Contains(t, result.Header, "Platform:")
	assert.Contains(t, result.Header, "API:")
	assert.Empty(t, result.Footer)
	assert.Empty(t, result.Highlights)
}

func Test_Summarize_windowsCRLF(t *testing.T) {
	log := "2026-06-10T13:10:38Z main - Version:               1.0.0\r\n" +
		"2026-06-10T13:10:38Z main - Platform:              linux amd64\r\n" +
		"2026-06-10T13:10:38Z main - < response [0xbbb]: 401 Unauthorized\r\n" +
		"2026-06-10T13:10:38Z main - ------------ Summary ------------\r\n" +
		"2026-06-10T13:10:38Z main - ------------ Errors ------------\r\n" +
		"2026-06-10T13:10:38Z main - ERROR:                 Auth error\r\n" +
		"2026-06-10T13:10:38Z main - Exit Code:             2\r\n"

	result := Summarize(log)

	assert.Contains(t, result.Header, "Version:")
	assert.Contains(t, result.Footer, "Exit Code:")
	require.NotEmpty(t, result.Highlights)
	assert.Equal(t, EventHTTPError, result.Highlights[0].Kind)
}

func Test_Summarize_3xxResponsesNotHighlighted(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - < response [0xaaa]: 301 Moved Permanently",
		"2026-06-10T13:10:38Z main - < response [0xbbb]: 304 Not Modified",
		"2026-06-10T13:10:38Z main - < response [0xccc]: 302 Found",
	}, "\n")

	assert.Empty(t, Summarize(log).Highlights)
}

func Test_Summarize_failedBoundaryNotPrefix(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - FailedOverNode rebalancing",
		"2026-06-10T13:10:38Z main - Failed to connect: timeout",
	}, "\n")

	result := Summarize(log)

	require.Len(t, result.Highlights, 1)
	assert.Equal(t, EventError, result.Highlights[0].Kind)
	assert.Contains(t, result.Highlights[0].Message, "Failed to connect")
}

func Test_Summarize_multipleDifferentHTTPErrors(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - < response [0xaaa]: 401 Unauthorized",
		"2026-06-10T13:10:38Z main - < response [0xbbb]: 500 Internal Server Error",
		"2026-06-10T13:10:38Z main - < response [0xccc]: 503 Service Unavailable",
	}, "\n")

	result := Summarize(log)

	require.Len(t, result.Highlights, 3)
	assert.Equal(t, EventHTTPError, result.Highlights[0].Kind)
	assert.Equal(t, EventHTTPError, result.Highlights[1].Kind)
	assert.Equal(t, EventHTTPError, result.Highlights[2].Kind)
}

func Test_Summarize_summaryMarkerButNoErrorsAndNoExitCode(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - < error: some failure",
		"2026-06-10T13:10:38Z main - ------------ Summary ------------",
		"2026-06-10T13:10:38Z main - Version:               1.0.0",
		"2026-06-10T13:10:38Z main - Platform:              darwin arm64",
	}, "\n")

	result := Summarize(log)

	require.Len(t, result.Highlights, 1)
	// The summary block content is in the footer since there's no errors/exit
	assert.NotEmpty(t, result.Footer)
}

func Test_Summarize_completelyUnprefixedLog(t *testing.T) {
	log := "some random output\nanother line\n"

	result := Summarize(log)

	assert.Empty(t, result.Header)
	assert.Empty(t, result.Highlights)
}

func Test_Summarize_headerWithDeeperIndentation(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Version:               1.0.0",
		"2026-06-10T13:10:38Z main - Checks:",
		"2026-06-10T13:10:38Z main -   Configuration:       all good",
		"2026-06-10T13:10:38Z main -     sub-item:          detail",
		"2026-06-10T13:10:38Z main - > request [0xaaa]: GET https://api.snyk.io",
	}, "\n")

	result := Summarize(log)

	assert.Contains(t, result.Header, "Checks:")
	assert.Contains(t, result.Header, "Configuration:")
	assert.Contains(t, result.Header, "sub-item:")
	assert.NotContains(t, result.Header, "request")
}

// =============================================================================
// CLIVersion and FormatSpecID in Summary
// =============================================================================

func Test_Summarize_populatesCLIVersion(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Version:               1.1200.0",
		"2026-06-10T13:10:38Z main - Platform:              darwin arm64",
	}, "\n")

	result := Summarize(log)

	assert.Equal(t, "1.1200.0", result.CLIVersion)
	assert.NotEmpty(t, result.FormatSpecID)
}

func Test_Summarize_noCLIVersionInLog(t *testing.T) {
	log := "2026-06-10T13:10:38Z main - < error: something\n"

	result := Summarize(log)

	assert.Empty(t, result.CLIVersion)
	assert.Equal(t, "base", result.FormatSpecID)
}
