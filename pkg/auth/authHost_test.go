package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_isValidAuthHost(t *testing.T) {
	testCases := []struct {
		authHost string
		expected bool
	}{
		{"api.au.snyk.io", true},
		{"api.example.snyk.io", true},
		{"api.snyk.io", true},
		{"api.snykgov.io", true},
		{"api.pre-release.snykgov.io", true},
		{"snyk.io", false},
		{"api.example.com", false},
	}

	for _, tc := range testCases {
		actual, err := isValidAuthHost(tc.authHost, `^api(\.(.+))?\.snyk|snykgov\.io$`)
		assert.NoError(t, err)

		if actual != tc.expected {
			t.Errorf("isValidAuthHost(%q) = %v, want %v", tc.authHost, actual, tc.expected)
		}
	}
}

func Test_FilterSupportedPatRegions(t *testing.T) {
	unsupported := []string{"https://api.snykgov.snyk.io"}
	tests := []struct {
		name               string
		regions            []string
		unsupportedRegions []string
		expected           []string
	}{
		{"empty regions", []string{}, unsupported, []string{}},
		{"default regions", []string{"https://api.snyk.io", "https://api.eu.snyk.io"}, unsupported, []string{"https://api.snyk.io", "https://api.eu.snyk.io"}},
		{"filtered regions", []string{"https://api.snyk.io", "https://api.snykgov.snyk.io"}, unsupported, []string{"https://api.snyk.io"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := FilterSupportedPatRegions(tt.regions, tt.unsupportedRegions)
			assert.ElementsMatch(t, tt.expected, actual)
		})
	}
}

func Test_ShuffleStrings(t *testing.T) {
	tests := []struct {
		name          string
		originalSlice []string
	}{
		{"empty slice", []string{}},
		{"single element slice", []string{"a"}},
		{"multiple elements slice", []string{"a", "b", "c", "d", "e"}},
		{"slice with duplicates", []string{"a", "b", "a", "c"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shuffledSlice := ShuffleStrings(tt.originalSlice)

			assert.ElementsMatch(t, tt.originalSlice, shuffledSlice)
		})
	}
}
