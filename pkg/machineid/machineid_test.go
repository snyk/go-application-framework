package machineid

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHasValue(t *testing.T) {
	tests := map[string]struct {
		input string
		want  bool
	}{
		"serial number": {
			input: "5CG1234ABC",
			want:  true,
		},
		"hostname": {
			input: "my-laptop.local",
			want:  true,
		},
		"uuid": {
			input: "550e8400-e29b-41d4-a716-446655440000",
			want:  true,
		},
		"mixed case": {
			input: "AbC-123",
			want:  true,
		},
		"brace-wrapped guid": {
			input: "{550E8400-E29B-41D4-A716-446655440000}",
			want:  true,
		},
		"surrounded by whitespace": {
			input: "  device-42  \n",
			want:  true,
		},
		"empty": {
			input: "",
			want:  false,
		},
		"whitespace only": {
			input: "   ",
			want:  false,
		},
		"over-length": {
			input: strings.Repeat("a", 129),
			want:  true,
		},
		"control characters": {
			input: "device\x00id",
			want:  true,
		},
		"leading dash": {
			input: "-device",
			want:  true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, hasValue(tc.input))
		})
	}
}

func TestGenerate(t *testing.T) {
	id := generate()
	require.True(t, hasValue(id))
	require.Equal(t, strings.ToLower(id), id, "generated id must be lowercase")

	other := generate()
	require.NotEqual(t, id, other, "successive calls must produce distinct ids")
}
