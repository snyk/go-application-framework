package conversion

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToInt(t *testing.T) {
	tests := []struct {
		name        string
		input       interface{}
		expected    int
		expectError bool
	}{
		{
			name:        "nil value returns error",
			input:       nil,
			expected:    0,
			expectError: true,
		},
		{
			name:        "int value returns same value",
			input:       42,
			expected:    42,
			expectError: false,
		},
		{
			name:        "negative int value",
			input:       -10,
			expected:    -10,
			expectError: false,
		},
		{
			name:        "string value parses correctly",
			input:       "123",
			expected:    123,
			expectError: false,
		},
		{
			name:        "negative string value",
			input:       "-5",
			expected:    -5,
			expectError: false,
		},
		{
			name:        "invalid string returns error",
			input:       "not-a-number",
			expected:    0,
			expectError: true,
		},
		{
			name:        "float32 value truncates",
			input:       float32(3.7),
			expected:    3,
			expectError: false,
		},
		{
			name:        "float64 value truncates",
			input:       float64(9.9),
			expected:    9,
			expectError: false,
		},
		{
			name:        "int64 value converts correctly",
			input:       int64(100),
			expected:    100,
			expectError: false,
		},
		{
			name:        "negative int64 value",
			input:       int64(-50),
			expected:    -50,
			expectError: false,
		},
		{
			name:        "large string value beyond 32-bit range",
			input:       "3000000000",
			expected:    3000000000,
			expectError: false,
		},
		{
			name:        "unsupported type returns error",
			input:       []int{1, 2, 3},
			expected:    0,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ToInt(tt.input)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expected, result)
		})
	}
}
