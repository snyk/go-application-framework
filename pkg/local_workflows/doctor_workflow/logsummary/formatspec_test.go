package logsummary

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// CLIVersion parsing
// =============================================================================

func TestParseCLIVersion_valid(t *testing.T) {
	tests := []struct {
		input string
		major int
		minor int
		patch int
	}{
		{"1.1200.0", 1, 1200, 0},
		{"2.0.0", 2, 0, 0},
		{"1.0.0-test", 1, 0, 0},
		{"0.0.1", 0, 0, 1},
		{"1.1300.5-beta.1", 1, 1300, 5},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			v, err := ParseCLIVersion(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.major, v.Major)
			assert.Equal(t, tt.minor, v.Minor)
			assert.Equal(t, tt.patch, v.Patch)
			assert.Equal(t, tt.input, v.Raw)
		})
	}
}

func TestParseCLIVersion_malformed(t *testing.T) {
	tests := []string{
		"",
		"not-a-version",
		"1.x.0",
		"1.0",
		"1.0.0.0",
		"abc.def.ghi",
	}

	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := ParseCLIVersion(input)
			assert.Error(t, err)
		})
	}
}

// =============================================================================
// VersionConstraint
// =============================================================================

func TestVersionConstraint_Contains(t *testing.T) {
	constraint := versionRange("1.1200.0", "2.0.0")

	tests := []struct {
		version  string
		expected bool
	}{
		{"1.1200.0", true},  // min inclusive
		{"1.1200.1", true},  // within range
		{"1.1300.0", true},  // within range
		{"1.1199.9", false}, // below min
		{"2.0.0", false},    // max exclusive
		{"2.0.1", false},    // above max
		{"0.0.1", false},    // well below
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			v, err := ParseCLIVersion(tt.version)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, constraint.Contains(v))
		})
	}
}

func TestVersionConstraint_UnboundedMax(t *testing.T) {
	constraint := versionRange("2.0.0", "")

	v1, _ := ParseCLIVersion("2.0.0")
	v2, _ := ParseCLIVersion("99.99.99")
	v3, _ := ParseCLIVersion("1.9999.0")

	assert.True(t, constraint.Contains(v1))
	assert.True(t, constraint.Contains(v2))
	assert.False(t, constraint.Contains(v3))
}

// =============================================================================
// extractCLIVersion
// =============================================================================

func TestExtractCLIVersion_findsVersionLine(t *testing.T) {
	lines := []string{
		"2026-06-10T13:10:38Z main - Using log level: debug",
		"2026-06-10T13:10:38Z main - Version:               1.1200.0",
		"2026-06-10T13:10:38Z main - Platform:              darwin arm64",
	}

	v, ok := extractCLIVersion(lines)
	require.True(t, ok)
	assert.Equal(t, 1, v.Major)
	assert.Equal(t, 1200, v.Minor)
	assert.Equal(t, "1.1200.0", v.Raw)
}

func TestExtractCLIVersion_missingVersionLine(t *testing.T) {
	lines := []string{
		"2026-06-10T13:10:38Z main - < error: something",
		"some other line",
	}

	_, ok := extractCLIVersion(lines)
	assert.False(t, ok)
}

func TestExtractCLIVersion_prefixedAndUnprefixed(t *testing.T) {
	// Prefixed version line
	lines1 := []string{"2026-06-10T13:10:38Z main - Version:               1.0.0"}
	v1, ok1 := extractCLIVersion(lines1)
	require.True(t, ok1)
	assert.Equal(t, "1.0.0", v1.Raw)

	// Unprefixed version line (e.g. in summary section)
	lines2 := []string{"Version:               1.0.0"}
	v2, ok2 := extractCLIVersion(lines2)
	require.True(t, ok2)
	assert.Equal(t, "1.0.0", v2.Raw)
}

func TestExtractCLIVersion_preReleaseVersion(t *testing.T) {
	lines := []string{"2026-06-10T13:10:38Z main - Version:               1.0.0-test"}
	v, ok := extractCLIVersion(lines)
	require.True(t, ok)
	assert.Equal(t, "1.0.0-test", v.Raw)
	assert.Equal(t, 1, v.Major)
	assert.Equal(t, 0, v.Minor)
}

// =============================================================================
// detectFormat
// =============================================================================

func TestDetectFormat_selectsCorrectSpec(t *testing.T) {
	// With only BaseSpec in registry, everything selects base
	lines := []string{"2026-06-10T13:10:38Z main - Version:               1.1200.0"}
	spec := detectFormat(lines)
	assert.Equal(t, "base", spec.ID)
}

func TestDetectFormat_fallsBackToBase(t *testing.T) {
	lines := []string{"no version here"}
	spec := detectFormat(lines)
	assert.Equal(t, "base", spec.ID)
}
