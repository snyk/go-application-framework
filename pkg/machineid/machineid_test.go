package machineid

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	tests := map[string]struct {
		input   string
		want    string
		wantErr bool
	}{
		"serial number": {
			input: "5CG1234ABC",
			want:  "5CG1234ABC",
		},
		"hostname": {
			input: "my-laptop.local",
			want:  "my-laptop.local",
		},
		"uuid": {
			input: "550e8400-e29b-41d4-a716-446655440000",
			want:  "550e8400-e29b-41d4-a716-446655440000",
		},
		"mixed case is preserved": {
			input: "AbC-123",
			want:  "AbC-123",
		},
		"brace-wrapped guid": {
			input: "{550E8400-E29B-41D4-A716-446655440000}",
			want:  "550E8400-E29B-41D4-A716-446655440000",
		},
		"surrounding whitespace is trimmed": {
			input: "  device-42  \n",
			want:  "device-42",
		},
		"empty": {
			input:   "",
			wantErr: true,
		},
		"whitespace only": {
			input:   "   ",
			wantErr: true,
		},
		"over-length": {
			input:   strings.Repeat("a", 129),
			wantErr: true,
		},
		"control characters": {
			input:   "device\x00id",
			wantErr: true,
		},
		"leading dash not allowed": {
			input:   "-device",
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := Validate(tc.input)
			if tc.wantErr {
				require.ErrorIs(t, err, ErrInvalidMachineID)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestGenerate(t *testing.T) {
	id := generate()
	_, err := Validate(id)
	require.NoError(t, err)
	require.Equal(t, strings.ToLower(id), id, "generated id must be lowercase")

	other := generate()
	require.NotEqual(t, id, other, "successive calls must produce distinct ids")
}
