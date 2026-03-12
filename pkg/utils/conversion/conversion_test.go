package conversion

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToInt64(t *testing.T) {
	tests := []struct {
		name        string
		input       interface{}
		expected    int64
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
			name:        "string value parses correctly",
			input:       "123",
			expected:    123,
			expectError: false,
		},
		{
			name:        "large string value beyond 32-bit range",
			input:       "3000000000",
			expected:    3000000000,
			expectError: false,
		},
		{
			name:        "int64 value returns same value",
			input:       int64(9223372036854775807),
			expected:    9223372036854775807,
			expectError: false,
		},
		{
			name:        "float64 value truncates",
			input:       float64(9.9),
			expected:    9,
			expectError: false,
		},
		{
			name:        "float32 value truncates",
			input:       float32(3.7),
			expected:    3,
			expectError: false,
		},
		{
			name:        "int8 value converts correctly",
			input:       int8(127),
			expected:    127,
			expectError: false,
		},
		{
			name:        "negative int8 value",
			input:       int8(-128),
			expected:    -128,
			expectError: false,
		},
		{
			name:        "int16 value converts correctly",
			input:       int16(32767),
			expected:    32767,
			expectError: false,
		},
		{
			name:        "int32 value converts correctly",
			input:       int32(2147483647),
			expected:    2147483647,
			expectError: false,
		},
		{
			name:        "uint value converts correctly",
			input:       uint(42),
			expected:    42,
			expectError: false,
		},
		{
			name:        "uint overflow returns error on 64-bit",
			input:       uint(math.MaxInt64) + 1,
			expected:    0,
			expectError: true,
		},
		{
			name:        "uint8 value converts correctly",
			input:       uint8(255),
			expected:    255,
			expectError: false,
		},
		{
			name:        "uint16 value converts correctly",
			input:       uint16(65535),
			expected:    65535,
			expectError: false,
		},
		{
			name:        "uint32 value converts correctly",
			input:       uint32(4294967295),
			expected:    4294967295,
			expectError: false,
		},
		{
			name:        "uint64 value converts correctly",
			input:       uint64(9223372036854775807),
			expected:    9223372036854775807,
			expectError: false,
		},
		{
			name:        "uint64 overflow returns error",
			input:       uint64(9223372036854775808),
			expected:    0,
			expectError: true,
		},
		{
			name:        "negative string value",
			input:       "-9223372036854775808",
			expected:    -9223372036854775808,
			expectError: false,
		},
		{
			name:        "invalid string returns error",
			input:       "not-a-number",
			expected:    0,
			expectError: true,
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
			result, err := ToInt64(tt.input)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expected, result)
		})
	}
}

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
			name:  "large string value beyond 32-bit range",
			input: "3000000000",
			expected: func() int {
				if math.MaxInt > 3000000000 {
					return 3000000000
				}
				return 0
			}(),
			expectError: math.MaxInt < 3000000000,
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
