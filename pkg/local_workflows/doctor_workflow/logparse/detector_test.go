package logparse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestDetector(registry []FormatSpec) *Detector {
	return NewDetector(testPrefixRe, []string{"Version:", "CLI Version:"}, registry, testSpec)
}

func TestDetector_ExtractCLIVersion_findsVersionLine(t *testing.T) {
	lines := []string{
		"2026-06-10T13:10:38Z main - Using log level: debug",
		"2026-06-10T13:10:38Z main - Version:               1.1200.0",
		"2026-06-10T13:10:38Z main - Platform:              darwin arm64",
	}

	v, ok := newTestDetector(nil).ExtractCLIVersion(lines)
	require.True(t, ok)
	assert.Equal(t, 1, v.Major)
	assert.Equal(t, 1200, v.Minor)
	assert.Equal(t, "1.1200.0", v.Raw)
}

func TestDetector_ExtractCLIVersion_missingVersionLine(t *testing.T) {
	lines := []string{
		"2026-06-10T13:10:38Z main - < error: something",
		"some other line",
	}

	_, ok := newTestDetector(nil).ExtractCLIVersion(lines)
	assert.False(t, ok)
}

func TestDetector_ExtractCLIVersion_prefixedAndUnprefixed(t *testing.T) {
	det := newTestDetector(nil)

	lines1 := []string{"2026-06-10T13:10:38Z main - Version:               1.0.0"}
	v1, ok1 := det.ExtractCLIVersion(lines1)
	require.True(t, ok1)
	assert.Equal(t, "1.0.0", v1.Raw)

	lines2 := []string{"Version:               1.0.0"}
	v2, ok2 := det.ExtractCLIVersion(lines2)
	require.True(t, ok2)
	assert.Equal(t, "1.0.0", v2.Raw)
}

func TestDetector_ExtractCLIVersion_preReleaseVersion(t *testing.T) {
	lines := []string{"2026-06-10T13:10:38Z main - Version:               1.0.0-test"}
	v, ok := newTestDetector(nil).ExtractCLIVersion(lines)
	require.True(t, ok)
	assert.Equal(t, "1.0.0-test", v.Raw)
	assert.Equal(t, 1, v.Major)
	assert.Equal(t, 0, v.Minor)
}

func TestDetector_Detect_selectsMatchingSpec(t *testing.T) {
	v2 := DeriveFormat(testSpec, "v2.0", VersionRange("2.0.0", ""))
	v1 := DeriveFormat(testSpec, "v1", VersionRange("1.0.0", "2.0.0"))
	det := newTestDetector([]FormatSpec{v2, v1})

	lines := []string{"2026-06-10T13:10:38Z main - Version:               1.5.0"}
	assert.Equal(t, "v1", det.Detect(lines).ID)

	linesV2 := []string{"2026-06-10T13:10:38Z main - Version:               2.3.0"}
	assert.Equal(t, "v2.0", det.Detect(linesV2).ID)
}

func TestDetector_Detect_fallsBackWhenNoVersion(t *testing.T) {
	det := newTestDetector([]FormatSpec{DeriveFormat(testSpec, "v2.0", VersionRange("2.0.0", ""))})
	assert.Equal(t, "test", det.Detect([]string{"no version here"}).ID)
}

func TestDetector_Detect_fallsBackWhenNoMatch(t *testing.T) {
	det := newTestDetector([]FormatSpec{DeriveFormat(testSpec, "v2.0", VersionRange("2.0.0", ""))})
	lines := []string{"2026-06-10T13:10:38Z main - Version:               1.0.0"}
	assert.Equal(t, "test", det.Detect(lines).ID)
}
