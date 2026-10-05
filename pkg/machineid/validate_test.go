package machineid

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValid(t *testing.T) {
	tests := map[string]struct {
		input string
		want  bool
	}{
		"serial number":                 {input: "5CG1234ABC", want: true},
		"hostname":                      {input: "my-laptop.local", want: true},
		"uuid":                          {input: "550e8400-e29b-41d4-a716-446655440000", want: true},
		"mixed case":                    {input: "AbC-123", want: true},
		"empty":                         {input: "", want: false},
		"whitespace only":               {input: "   ", want: false},
		"over-length":                   {input: strings.Repeat("a", 129), want: false},
		"exactly max length":            {input: strings.Repeat("a", 128), want: true},
		"leading dash":                  {input: "-device", want: false},
		"brace-wrapped guid":            {input: "{550E8400-E29B-41D4-A716-446655440000}", want: false},
		"control character":             {input: "device\x00id", want: false},
		"embedded newline":              {input: "device\nid", want: false},
		"embedded carriage return":      {input: "device\rid", want: false},
		"embedded space":                {input: "device id", want: false},
		"placeholder zero":              {input: "0", want: false},
		"placeholder none":              {input: "none", want: false},
		"placeholder none mixed case":   {input: "None", want: false},
		"placeholder oem":               {input: "to be filled by o.e.m.", want: false},
		"placeholder oem uppercase":     {input: "TO BE FILLED BY O.E.M.", want: false},
		"placeholder not applicable":    {input: "not applicable", want: false},
		"placeholder not specified":     {input: "not specified", want: false},
		"placeholder default string":    {input: "default string", want: false},
		"placeholder invalid":           {input: "invalid", want: false},
		"placeholder n/a":               {input: "n/a", want: false},
		"lookalike of placeholder zero": {input: "01", want: true},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, valid(tc.input))
		})
	}
}

func TestInvalidReasonIsOnlyUsedForRejectedValues(t *testing.T) {
	tests := map[string]string{
		"":                       "empty",
		strings.Repeat("a", 129): "longer than 128 characters",
		"device id":              "contains characters outside the allowed set",
		"none":                   "matches a known placeholder serial number",
	}
	for input, wantSubstring := range tests {
		require.False(t, valid(input))
		require.Contains(t, invalidReason(input), wantSubstring)
	}
}
