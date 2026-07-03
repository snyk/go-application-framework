package diagnosis

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorEventCheck_detectsCLIErrors(t *testing.T) {
	lines := []ParsedLine{
		{Number: 1, Message: "< error: Authentication error", HasCLIPrefix: true},
		{Number: 2, Message: "Failed to determine default value", HasCLIPrefix: true},
	}

	check := &ErrorEventCheck{}
	findings := check.Analyze(lines)

	require.Len(t, findings, 2)
	assert.Equal(t, KindCLIError, findings[0].Kind)
	assert.Equal(t, ProducerLogAnalysis, findings[0].Producer)
	assert.Equal(t, SeverityError, findings[0].Severity)
	assert.Equal(t, "L1", findings[0].Subject)
	assert.Equal(t, []int{1}, findings[0].Lines)
	assert.Equal(t, KindCLIError, findings[1].Kind)
}

func TestErrorEventCheck_ignoresResponseLines(t *testing.T) {
	// HTTP responses are handled by CorrelationCheck, not this check.
	lines := []ParsedLine{
		{Number: 1, Message: "< response [0x2b3cd0a17cc0]: 401 Unauthorized", HasCLIPrefix: true},
		{Number: 2, Message: "< response [0x2b3cd0a17cc0]: 200 OK", HasCLIPrefix: true},
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
			Message:      "< error: Authentication error",
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

func TestDefaultLogChecks(t *testing.T) {
	checks := DefaultLogChecks()
	require.Len(t, checks, 2)
	assert.Equal(t, "http-correlation", checks[0].Name())
	assert.Equal(t, "error-events", checks[1].Name())

	// A realistic snippet: an HTTP error (correlation) and a CLI error (events).
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - < response [0x2b3cd0a17cc0]: 401 Unauthorized",
		"2026-06-10T13:10:38Z main - < error: something broke",
	}, "\n")
	parsed, err := ParseLines(strings.NewReader(log))
	require.NoError(t, err)
	_, body, _ := SplitSections(parsed)

	var findings []Finding
	for _, c := range checks {
		findings = append(findings, c.Analyze(body)...)
	}

	var hasCorrelation, hasCLI bool
	for _, f := range findings {
		switch f.Kind {
		case KindCorrelation:
			hasCorrelation = true
		case KindCLIError:
			hasCLI = true
		default:
		}
	}
	assert.True(t, hasCorrelation, "expected correlation finding for the 401")
	assert.True(t, hasCLI, "expected CLI error finding")
}
