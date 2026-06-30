package logsummary

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSummarize_detectsBaseVersion(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Version:               1.0.0",
		"2026-06-10T13:10:38Z main - Platform:              darwin arm64",
		"2026-06-10T13:10:38Z main - < response [0xbbb]: 401 Unauthorized",
		"2026-06-10T13:10:38Z main - Exit Code:             2",
	}, "\n")

	result := Summarize(log)

	assert.Equal(t, "1.0.0", result.CLIVersion)
	assert.Equal(t, "base", result.FormatSpecID)
	require.Len(t, result.Highlights, 1)
	assert.Equal(t, EventHTTPError, result.Highlights[0].Kind)
}

func TestSummarize_unknownFutureVersionFallsBack(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Version:               99.0.0",
		"2026-06-10T13:10:38Z main - Platform:              darwin arm64",
		"2026-06-10T13:10:38Z main - < error: something",
		"2026-06-10T13:10:38Z main - Exit Code:             1",
	}, "\n")

	result := Summarize(log)

	assert.Equal(t, "99.0.0", result.CLIVersion)
	// Should fall back to base (or latest known), not panic
	assert.NotEmpty(t, result.FormatSpecID)
	require.Len(t, result.Highlights, 1)
	assert.Equal(t, EventError, result.Highlights[0].Kind)
}

func TestSummarize_twoVersionsSameEngine(t *testing.T) {
	// Save and restore registry for this test
	origRegistry := registry
	defer func() { registry = origRegistry }()

	// Register a v2 spec with a different summary marker
	v2Spec := DeriveFormat(BaseSpec, "v2.0", versionRange("2.0.0", ""),
		WithLexerOverrides(
			WithSummaryMarker("============ Summary ============"),
		),
	)
	registry = []FormatSpec{v2Spec, BaseSpec}

	// Log in v1 format (old markers)
	v1Log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Version:               1.0.0",
		"2026-06-10T13:10:38Z main - < error: v1 failure",
		"2026-06-10T13:10:38Z main - ------------ Summary ------------",
		"2026-06-10T13:10:38Z main - ------------ Errors ------------",
		"2026-06-10T13:10:38Z main - Exit Code:             1",
	}, "\n")

	// Log in v2 format (new markers)
	v2Log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Version:               2.0.0",
		"2026-06-10T13:10:38Z main - < error: v2 failure",
		"2026-06-10T13:10:38Z main - ============ Summary ============",
		"2026-06-10T13:10:38Z main - ============ Errors ============",
		"2026-06-10T13:10:38Z main - Exit Code:             1",
	}, "\n")

	result1 := Summarize(v1Log)
	result2 := Summarize(v2Log)

	assert.Equal(t, "base", result1.FormatSpecID)
	assert.Equal(t, "v2.0", result2.FormatSpecID)

	require.Len(t, result1.Highlights, 1)
	assert.Contains(t, result1.Highlights[0].Message, "v1 failure")

	require.Len(t, result2.Highlights, 1)
	assert.Contains(t, result2.Highlights[0].Message, "v2 failure")

	// v1 log should split on old summary marker
	assert.Contains(t, result1.Footer, "Exit Code:")

	// v2 log should split on new summary marker
	assert.Contains(t, result2.Footer, "Exit Code:")
}

func TestSummarize_derivedSpecWithExtraClassifier(t *testing.T) {
	origRegistry := registry
	defer func() { registry = origRegistry }()

	v2Spec := DeriveFormat(BaseSpec, "v2.0", versionRange("2.0.0", ""),
		WithLexerOverrides(
			WithExtraClassifier(
				func(msg string) bool { return strings.HasPrefix(msg, "FATAL ") },
				TokenCLIError,
			),
		),
	)
	registry = []FormatSpec{v2Spec, BaseSpec}

	// Base spec should NOT highlight FATAL lines
	v1Log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Version:               1.0.0",
		"2026-06-10T13:10:38Z main - FATAL something crashed",
	}, "\n")

	result1 := Summarize(v1Log)
	assert.Empty(t, result1.Highlights, "base spec should not match FATAL")

	// V2 spec should highlight FATAL lines
	v2Log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Version:               2.0.0",
		"2026-06-10T13:10:38Z main - FATAL something crashed",
	}, "\n")

	result2 := Summarize(v2Log)
	require.Len(t, result2.Highlights, 1)
	assert.Equal(t, EventError, result2.Highlights[0].Kind)
	assert.Contains(t, result2.Highlights[0].Message, "FATAL something crashed")
}
