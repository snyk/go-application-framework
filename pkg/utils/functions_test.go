package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsEmpty(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		expected bool
	}{
		// Nil values
		{
			name:     "nil interface",
			value:    nil,
			expected: true,
		},
		{
			name:     "nil pointer",
			value:    (*string)(nil),
			expected: true,
		},
		{
			name:     "nil interface containing nil pointer",
			value:    interface{}((*int)(nil)),
			expected: true,
		},

		// Zero values
		{
			name:     "zero int",
			value:    0,
			expected: true,
		},
		{
			name:     "zero int64",
			value:    int64(0),
			expected: true,
		},
		{
			name:     "zero float64",
			value:    0.0,
			expected: true,
		},
		{
			name:     "empty string",
			value:    "",
			expected: true,
		},
		{
			name:     "false boolean",
			value:    false,
			expected: true,
		},

		// Non-zero values
		{
			name:     "non-zero int",
			value:    42,
			expected: false,
		},
		{
			name:     "non-zero float",
			value:    3.14,
			expected: false,
		},
		{
			name:     "non-empty string",
			value:    "hello",
			expected: false,
		},
		{
			name:     "true boolean",
			value:    true,
			expected: false,
		},

		// Pointers to non-zero values
		{
			name:     "pointer to non-zero int",
			value:    func() *int { i := 42; return &i }(),
			expected: false,
		},
		{
			name:     "pointer to non-empty string",
			value:    func() *string { s := "hello"; return &s }(),
			expected: false,
		},
		{
			name:     "pointer to true boolean",
			value:    func() *bool { b := true; return &b }(),
			expected: false,
		},

		// Pointers to zero values
		{
			name:     "pointer to zero int",
			value:    func() *int { i := 0; return &i }(),
			expected: true,
		},
		{
			name:     "pointer to empty string",
			value:    func() *string { s := ""; return &s }(),
			expected: true,
		},
		{
			name:     "pointer to false boolean",
			value:    func() *bool { b := false; return &b }(),
			expected: true,
		},

		// Slices
		{
			name:     "nil slice",
			value:    []string(nil),
			expected: true,
		},
		{
			name:     "empty slice",
			value:    []string{},
			expected: true,
		},
		{
			name:     "non-empty slice",
			value:    []string{"hello"},
			expected: false,
		},
		{
			name:     "slice with empty string",
			value:    []string{""},
			expected: false,
		},

		// Maps
		{
			name:     "nil map",
			value:    map[string]int(nil),
			expected: true,
		},
		{
			name:     "empty map",
			value:    map[string]int{},
			expected: true,
		},
		{
			name:     "non-empty map",
			value:    map[string]int{"key": 42},
			expected: false,
		},
		{
			name:     "map with zero value",
			value:    map[string]int{"key": 0},
			expected: false,
		},

		// Channels
		{
			name:     "nil channel",
			value:    (chan int)(nil),
			expected: true,
		},
		{
			name:     "non-nil channel",
			value:    make(chan int),
			expected: false,
		},

		// Functions
		{
			name:     "nil function",
			value:    (func())(nil),
			expected: true,
		},
		{
			name:     "non-nil function",
			value:    func() {},
			expected: false,
		},

		// Structs
		{
			name:     "empty struct",
			value:    struct{}{},
			expected: true,
		},
		{
			name:     "struct with zero fields",
			value:    struct{ Name string }{},
			expected: true,
		},
		{
			name:     "struct with non-zero fields",
			value:    struct{ Name string }{Name: "test"},
			expected: false,
		},

		// Multiple levels of pointers
		{
			name:     "pointer to pointer to nil",
			value:    func() **string { var p *string; return &p }(),
			expected: true,
		},
		{
			name:     "pointer to pointer to value",
			value:    func() **string { s := "hello"; p := &s; return &p }(),
			expected: false,
		},

		// Interface containing values
		{
			name:     "interface containing zero value",
			value:    interface{}(0),
			expected: true,
		},
		{
			name:     "interface containing non-zero value",
			value:    interface{}(42),
			expected: false,
		},
		{
			name:     "interface containing empty slice",
			value:    interface{}([]string{}),
			expected: true,
		},
		{
			name:     "interface containing non-empty slice",
			value:    interface{}([]string{"hello"}),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsEmpty(tt.value)
			assert.Equal(t, tt.expected, result, "IsEmpty(%v) should return %v", tt.value, tt.expected)
		})
	}
}

func TestIsEmpty_EdgeCases(t *testing.T) {
	t.Run("custom struct with IsZero method", func(t *testing.T) {
		// Test with a custom type that has its own zero value semantics
		type CustomStruct struct {
			Value int
		}

		// Zero value struct
		result := IsEmpty(CustomStruct{})
		assert.True(t, result)

		// Non-zero value struct
		result = IsEmpty(CustomStruct{Value: 42})
		assert.False(t, result)
	})

	t.Run("deeply nested pointers", func(t *testing.T) {
		// Create a chain of pointers
		value := "hello"
		ptr1 := &value
		ptr2 := &ptr1
		ptr3 := &ptr2

		result := IsEmpty(ptr3)
		assert.False(t, result)

		// Test with nil in the chain
		var nilPtr *string
		ptrToNil := &nilPtr
		result = IsEmpty(ptrToNil)
		assert.True(t, result)
	})

	t.Run("interface containing interface", func(t *testing.T) {
		var inner interface{} = 42
		var outer interface{} = inner

		result := IsEmpty(outer)
		assert.False(t, result)

		// Test with nil inner interface
		inner = nil
		outer = inner
		result = IsEmpty(outer)
		assert.True(t, result)
	})
}
