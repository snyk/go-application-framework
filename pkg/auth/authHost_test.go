package auth

import (
	"testing"

	"github.com/snyk/go-application-framework/pkg/utils"
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
		actual, err := utils.MatchesRegex(tc.authHost, `^api(\.(.+))?\.snyk|snykgov\.io$`)
		assert.NoError(t, err)

		if actual != tc.expected {
			t.Errorf("isValidAuthHost(%q) = %v, want %v", tc.authHost, actual, tc.expected)
		}
	}
}
