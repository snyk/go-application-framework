package auth

import (
	"testing"

	"github.com/snyk/go-application-framework/internal/constants"
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
		{"api.a.b.c.snyk.io", true},
		{"snyk.io", false},
		{"api.example.com", false},
		{"api.snyk.evil.com", false},
		{"evilsnykgov.io", false},
		{"api.example.snyk.io.evil.com", false},
		{"api.snyk.io.attacker.com", false},
		{"api.snyk.io/haha", false},
		{"api.attacker.io/haha.snyk.io", false},
		{"token@api.snyk.io", false},
		{"api.something api.snyk.io", false},
	}

	for _, tc := range testCases {
		actual, err := IsValidAuthHost(tc.authHost, constants.SNYK_DEFAULT_ALLOWED_HOST_REGEXP)
		assert.NoError(t, err)

		if actual != tc.expected {
			t.Errorf("isValidAuthHost(%q) = %v, want %v", tc.authHost, actual, tc.expected)
		}
	}
}
