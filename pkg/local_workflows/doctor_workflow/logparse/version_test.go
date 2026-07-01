package logparse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestVersionConstraint_Contains(t *testing.T) {
	constraint := VersionRange("1.1200.0", "2.0.0")

	tests := []struct {
		version  string
		expected bool
	}{
		{"1.1200.0", true},
		{"1.1200.1", true},
		{"1.1300.0", true},
		{"1.1199.9", false},
		{"2.0.0", false},
		{"2.0.1", false},
		{"0.0.1", false},
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
	constraint := VersionRange("2.0.0", "")

	v1, err := ParseCLIVersion("2.0.0")
	require.NoError(t, err)
	v2, err := ParseCLIVersion("99.99.99")
	require.NoError(t, err)
	v3, err := ParseCLIVersion("1.9999.0")
	require.NoError(t, err)

	assert.True(t, constraint.Contains(v1))
	assert.True(t, constraint.Contains(v2))
	assert.False(t, constraint.Contains(v3))
}

func TestCLIVersion_IsZero(t *testing.T) {
	assert.True(t, CLIVersion{}.IsZero())
	assert.False(t, NewCLIVersion(1, 0, 0, "1.0.0").IsZero())
}
