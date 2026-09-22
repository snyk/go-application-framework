package machineid

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseIoregPlatformSerial(t *testing.T) {
	tests := map[string]struct {
		output string
		want   string
		wantOK bool
	}{
		"typical ioreg output": {
			output: `+-o Root  <class IORegistryEntryRoot, id 0x100000100, retain 39>
  +-o MacBookPro18,1  <class IOPlatformExpertDevice, id 0x100000310, registered, matched, active, busy 0 (0 ms), retain 41>
    {
      "IOPlatformUUID" = "12345678-ABCD-1234-ABCD-1234567890AB"
      "IOPlatformSerialNumber" = "C02ABC1DEF23"
    }
`,
			want:   "C02ABC1DEF23",
			wantOK: true,
		},
		"missing serial number field": {
			output: `{
      "IOPlatformUUID" = "12345678-ABCD-1234-ABCD-1234567890AB"
    }`,
			wantOK: false,
		},
		"empty serial number field": {
			output: `"IOPlatformSerialNumber" = ""`,
			want:   "",
			wantOK: true,
		},
		"empty output": {
			output: "",
			wantOK: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := parseIoregPlatformSerial([]byte(tc.output))
			require.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				require.Equal(t, tc.want, got)
			}
		})
	}
}
