//go:build darwin

package identity

import (
	"os"
	"testing"
)

func TestSerialNumber_Darwin(t *testing.T) {
	if os.Getenv(hardwareTestsEnv) != "1" {
		t.Skipf("set %s=1 to read the real hardware serial", hardwareTestsEnv)
	}

	serial, err := SerialNumber()
	if err != nil {
		t.Fatalf("SerialNumber() error = %v", err)
	}
	if serial == "" {
		t.Skip("hardware reports no usable serial")
	}
}

func TestReadSerial_Darwin(t *testing.T) {
	if os.Getenv(hardwareTestsEnv) != "1" {
		t.Skipf("set %s=1 to read the real hardware serial", hardwareTestsEnv)
	}

	serial, err := readSerial()
	if err != nil {
		t.Fatalf("readSerial() error = %v", err)
	}
	if serial == "" {
		t.Skip("hardware reports no serial")
	}
}

func TestParseIORegSerial(t *testing.T) {
	t.Parallel()

	const sampleOutput = `+-o IOPlatformExpertDevice  <class IOPlatformExpertDevice, id 0x1000001d2, registered, matched, active, busy 0 (0 ms), retain 8>
  {
    "IOPlatformSerialNumber" = "C02Q7KHTGFWF"
    "IOPlatformUUID" = "E0E1E2E3-E4E5-E6E7-E8E9-EAEBECEDEEEF"
  }
`

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "extracts serial from sample ioreg output",
			input: sampleOutput,
			want:  "C02Q7KHTGFWF",
		},
		{
			name:  "empty serial value is a successful parse",
			input: `"IOPlatformSerialNumber" = ""`,
			want:  "",
		},
		{
			name:    "missing key",
			input:   `"IOPlatformUUID" = "abc"`,
			wantErr: true,
		},
		{
			name:    "malformed line",
			input:   `"IOPlatformSerialNumber" = C02Q7KHTGFWF`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseIORegSerial([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseIORegSerial() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("parseIORegSerial() = %q, want %q", got, tt.want)
			}
		})
	}
}
