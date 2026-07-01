package diagnosis

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLines_basic(t *testing.T) {
	input := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Version:               1.0.0",
		"2026-06-10T13:10:38Z main - Platform:              darwin arm64",
		"plain line without prefix",
	}, "\n")

	lines, err := ParseLines(strings.NewReader(input))
	require.NoError(t, err)
	require.Len(t, lines, 3)

	assert.Equal(t, 1, lines[0].Number)
	assert.Equal(t, "Version:               1.0.0", lines[0].Message)
	assert.True(t, lines[0].HasCLIPrefix)

	assert.Equal(t, 3, lines[2].Number)
	assert.Equal(t, "plain line without prefix", lines[2].Message)
	assert.False(t, lines[2].HasCLIPrefix)
}

func TestSplitSections_withSummaryAndErrors(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - < error: real failure",
		"2026-06-10T13:10:38Z main - ------------ Summary ------------",
		"2026-06-10T13:10:38Z main - < error: reprinted noise",
		"2026-06-10T13:10:38Z main - ------------ Errors ------------",
		"2026-06-10T13:10:38Z main - ERROR:                 Auth error (SNYK-0005)",
		"2026-06-10T13:10:38Z main - Exit Code:             2",
	}, "\n")

	lines, err := ParseLines(strings.NewReader(log))
	require.NoError(t, err)

	_, body, footer := SplitSections(lines)

	require.Len(t, body, 1)
	assert.Equal(t, "< error: real failure", body[0].Message)

	require.NotEmpty(t, footer)
	messages := collectMessages(footer)
	assert.Contains(t, messages, errorsMarker)
	assert.Contains(t, messages, "Auth error (SNYK-0005)")
}

func TestSplitSections_exitCodeWithoutSummary(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - < error: real failure",
		"2026-06-10T13:10:38Z main - Exit Code:             2",
	}, "\n")

	lines, err := ParseLines(strings.NewReader(log))
	require.NoError(t, err)

	_, body, footer := SplitSections(lines)

	require.Len(t, body, 1)
	assert.Equal(t, "Exit Code:             2", footer[0].Message)
}

func TestSplitSections_noFooter(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Using log level: debug",
		"2026-06-10T13:10:38Z main - < response [0x2b3cd0a17cc0]: 500 Internal Server Error",
	}, "\n")

	lines, err := ParseLines(strings.NewReader(log))
	require.NoError(t, err)

	_, body, footer := SplitSections(lines)

	assert.Len(t, body, 2)
	assert.Empty(t, footer)
}

func TestExtractSummary_parsesKeyValues(t *testing.T) {
	header := []ParsedLine{
		{Number: 1, Message: "Version:               1.0.0", HasCLIPrefix: true},
		{Number: 2, Message: "Platform:              darwin arm64", HasCLIPrefix: true},
		{Number: 3, Message: "Checks:", HasCLIPrefix: true},
		{Number: 4, Message: "  Configuration:       all good", HasCLIPrefix: true},
	}

	summary := ExtractSummary(header)

	require.Len(t, summary.Fields, 3)
	assert.Equal(t, "Version", summary.Fields[0].Key)
	assert.Equal(t, "1.0.0", summary.Fields[0].Value)
	assert.Equal(t, "Platform", summary.Fields[1].Key)
	assert.Equal(t, "darwin arm64", summary.Fields[1].Value)
	// Continuation line appends to Checks
	assert.Equal(t, "Checks", summary.Fields[2].Key)
	assert.Contains(t, summary.Fields[2].Value, "Configuration:")

	assert.Contains(t, summary.Raw, "Version:")
	assert.Contains(t, summary.Raw, "Configuration:")
}

func TestExtractSummary_empty(t *testing.T) {
	summary := ExtractSummary(nil)
	assert.Empty(t, summary.Fields)
	assert.Empty(t, summary.Raw)
}

func TestSplitSections_headerExtracted(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Using log level: debug",
		"2026-06-10T13:10:38Z main - Version:               1.0.0",
		"2026-06-10T13:10:38Z main - Platform:              darwin arm64",
		"2026-06-10T13:10:38Z main - < response [0x2b3cd0a17cc0]: 500 Internal Server Error",
	}, "\n")

	lines, err := ParseLines(strings.NewReader(log))
	require.NoError(t, err)

	header, _, _ := SplitSections(lines)

	require.Len(t, header, 2)
	assert.Equal(t, "Version:               1.0.0", header[0].Message)
	assert.Equal(t, "Platform:              darwin arm64", header[1].Message)
}

func TestSplitSections_unknownHeaderFieldIncluded(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Version:               1.0.0",
		"2026-06-10T13:10:38Z main - Some New Field:        a value",
		"2026-06-10T13:10:38Z main - > request [0x2b3cd0a17cc0]: GET https://api.snyk.io",
	}, "\n")

	lines, err := ParseLines(strings.NewReader(log))
	require.NoError(t, err)

	header, _, _ := SplitSections(lines)

	require.Len(t, header, 2)
	assert.Equal(t, "Some New Field:        a value", header[1].Message)
}

func TestSplitSections_eventAfterHeaderNotSwallowed(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Version:               1.0.0",
		"2026-06-10T13:10:38Z main - Platform:              darwin arm64",
		"2026-06-10T13:10:38Z main - Failed to fetch organizations: auth failed",
	}, "\n")

	lines, err := ParseLines(strings.NewReader(log))
	require.NoError(t, err)

	header, body, _ := SplitSections(lines)

	require.Len(t, header, 2)
	assert.Equal(t, "Platform:              darwin arm64", header[1].Message)
	// The "Failed to fetch" line should remain in body, not absorbed into header
	assert.Len(t, body, 3)
}

func TestSplitSections_embeddedMarkersDoNotDelimit(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - < error: real failure",
		"2026-06-10T13:10:38Z main - Failed to parse " + summaryMarker,
		"2026-06-10T13:10:38Z main - Failed to parse " + errorsMarker,
	}, "\n")

	lines, err := ParseLines(strings.NewReader(log))
	require.NoError(t, err)

	_, body, footer := SplitSections(lines)

	assert.Empty(t, footer)
	assert.Len(t, body, 3)
}

func TestSplitSections_unprefixedMarkersStillDelimit(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - < error: real failure",
		summaryMarker,
		"Version:               1.0.0",
		errorsMarker,
		"ERROR:                 Auth error (SNYK-0005)",
		"Exit Code:             2",
	}, "\n")

	lines, err := ParseLines(strings.NewReader(log))
	require.NoError(t, err)

	_, body, footer := SplitSections(lines)

	require.Len(t, body, 1)
	messages := collectMessages(footer)
	assert.Contains(t, messages, errorsMarker)
	assert.Contains(t, messages, "Auth error (SNYK-0005)")
	assert.NotContains(t, messages, "Version:")
}

func collectMessages(lines []ParsedLine) string {
	var sb strings.Builder
	for _, ln := range lines {
		sb.WriteString(ln.Message)
		sb.WriteString("\n")
	}
	return sb.String()
}
