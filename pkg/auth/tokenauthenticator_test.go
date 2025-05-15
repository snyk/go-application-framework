package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsAuthTypePAT(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected bool
	}{
		// Valid PATs
		{
			name:     "Valid UAT PAT",
			token:    "snyk_uat.1a2b3c4d.mySuperSecret_Token-Value.aChecksum_123-Value",
			expected: true,
		},
		{
			name:     "Valid SAT PAT",
			token:    "snyk_sat.abcdef12.another-token_VALUE.more_checksum-STUFF",
			expected: true,
		},
		{
			name:     "Valid PAT with all numbers in kid",
			token:    "snyk_uat.01234567.secret.checksum",
			expected: true,
		},
		{
			name:     "Valid PAT with minimal secret and checksum",
			token:    "snyk_sat.87654321.s.c",
			expected: true,
		},
		{
			name:     "Valid PAT with hyphens and underscores",
			token:    "snyk_uat.11223344.sec-ret_val.check-sum_VAL",
			expected: true,
		},

		// Invalid PATs
		{
			name:     "Completely random string",
			token:    "thisisnotapat",
			expected: false,
		},
		{
			name:     "Legacy Snyk API token format",
			token:    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			expected: false,
		},
		{
			name:     "Empty string",
			token:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := IsAuthTypePAT(tt.token)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestIsAuthTypeToken(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		expected bool
	}{
		{
			name:     "Valid UUID",
			token:    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
			expected: true,
		},
		{
			name:     "Valid UUID with uppercase",
			token:    "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
			expected: true,
		},
		{
			name:     "Invalid UUID - too short",
			token:    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeee",
			expected: false,
		},
		{
			name:     "Invalid UUID - invalid characters",
			token:    "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
			expected: false,
		},
		{
			name:     "Empty string",
			token:    "",
			expected: false,
		},
		{
			name:     "Snyk PAT",
			token:    "snyk_uat.1a2b3c4d.mySuperSecret_Token-Value.aChecksum_123-Value",
			expected: false,
		},
		{
			name:     "Random string",
			token:    "thisisnotauuid",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := IsAuthTypeToken(tt.token)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
