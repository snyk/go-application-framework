//go:build windows

package identity

import (
	"os"
	"testing"
)

func TestSerialNumber_Windows(t *testing.T) {
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

func TestReadSerial_Windows(t *testing.T) {
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
