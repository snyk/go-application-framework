package diagnosis

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorEventCheck_detectsHTTPErrors(t *testing.T) {
	lines := []ParsedLine{
		{Number: 1, Message: "< response [0x2b3cd0a17cc0]: 401 Unauthorized", HasCLIPrefix: true},
		{Number: 2, Message: "< response [0x2b3cd0a17cc0]: 500 Internal Server Error", HasCLIPrefix: true},
	}

	check := &ErrorEventCheck{}
	findings := check.Analyze(lines)

	require.Len(t, findings, 2)
	assert.Equal(t, KindHTTPError, findings[0].Kind)
	assert.Equal(t, SourceLogAnalysis, findings[0].Source)
	assert.Equal(t, SeverityError, findings[0].Severity)
	assert.Equal(t, "L1", findings[0].Subject)
}

func TestErrorEventCheck_detectsCLIErrors(t *testing.T) {
	lines := []ParsedLine{
		{Number: 1, Message: "< error: Authentication error", HasCLIPrefix: true},
		{Number: 2, Message: "Failed to determine default value", HasCLIPrefix: true},
	}

	check := &ErrorEventCheck{}
	findings := check.Analyze(lines)

	require.Len(t, findings, 2)
	assert.Equal(t, KindCLIError, findings[0].Kind)
	assert.Equal(t, KindCLIError, findings[1].Kind)
}

func TestErrorEventCheck_successfulResponsesNotHighlighted(t *testing.T) {
	lines := []ParsedLine{
		{Number: 1, Message: "< response [0x2b3cd0a17cc0]: 200 OK", HasCLIPrefix: true},
		{Number: 2, Message: "< response [0x2b3cd0a17cc0]: 304 Not Modified", HasCLIPrefix: true},
	}

	check := &ErrorEventCheck{}
	assert.Empty(t, check.Analyze(lines))
}

func TestErrorEventCheck_ignoresUnprefixedLines(t *testing.T) {
	lines := []ParsedLine{
		{Number: 1, Message: "< error: something", HasCLIPrefix: false},
	}

	check := &ErrorEventCheck{}
	assert.Empty(t, check.Analyze(lines))
}

func TestErrorEventCheck_dedupesRepeatedEvents(t *testing.T) {
	lines := make([]ParsedLine, 10)
	for i := range lines {
		lines[i] = ParsedLine{
			Number:       i + 1,
			Message:      "< response [0x2b3cd0a17cc0]: 401 Unauthorized",
			HasCLIPrefix: true,
		}
	}

	check := &ErrorEventCheck{}
	findings := check.Analyze(lines)

	require.Len(t, findings, 1)
	assert.Equal(t, "L1", findings[0].Subject)
}

func TestErrorEventCheck_highlightCap(t *testing.T) {
	lines := make([]ParsedLine, maxHighlights+50)
	for i := range lines {
		lines[i] = ParsedLine{
			Number:       i + 1,
			Message:      fmt.Sprintf("< error: failure %d", i),
			HasCLIPrefix: true,
		}
	}

	check := &ErrorEventCheck{}
	findings := check.Analyze(lines)

	assert.Len(t, findings, maxHighlights)
}

func TestErrorEventCheck_responseRequiresStatusLineShape(t *testing.T) {
	lines := []ParsedLine{
		{Number: 1, Message: "sending response to: 404 handler", HasCLIPrefix: true},
		{Number: 2, Message: "< response [0xbbb]: 503 Service Unavailable", HasCLIPrefix: true},
	}

	check := &ErrorEventCheck{}
	findings := check.Analyze(lines)

	require.Len(t, findings, 1)
	assert.Equal(t, KindHTTPError, findings[0].Kind)
	assert.Contains(t, findings[0].Message, "503 Service Unavailable")
}

func TestDefaultLogChecks(t *testing.T) {
	checks := DefaultLogChecks()
	require.Len(t, checks, 1)
	assert.Equal(t, "error-events", checks[0].Name())

	// Verify it finds events in a realistic log snippet.
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - < response [0x2b3cd0a17cc0]: 401 Unauthorized",
		"2026-06-10T13:10:38Z main - < error: something broke",
	}, "\n")
	parsed, err := ParseLines(strings.NewReader(log))
	require.NoError(t, err)

	_, body, _ := SplitSections(parsed)
	findings := checks[0].Analyze(body)
	assert.Len(t, findings, 2)
}
