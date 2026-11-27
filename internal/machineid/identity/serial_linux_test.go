//go:build linux

package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadSerialFromPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "product_serial")
	if err := os.WriteFile(path, []byte("TEST-SERIAL-123\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	got, err := readSerialFromPath(path)
	if err != nil {
		t.Fatalf("readSerialFromPath() error = %v", err)
	}
	if got != "TEST-SERIAL-123" {
		t.Errorf("readSerialFromPath() = %q, want %q", got, "TEST-SERIAL-123")
	}
}

func TestSerialNumber_Linux_Integration(t *testing.T) {
	if os.Getenv(hardwareTestsEnv) != "1" {
		t.Skipf("set %s=1 to read the real hardware serial", hardwareTestsEnv)
	}
	if os.Geteuid() != 0 {
		t.Skip("Linux serial read from sysfs requires root")
	}
	if _, err := os.Stat(linuxSerialPath); err != nil {
		t.Skipf("sysfs serial path unavailable: %v", err)
	}

	_, err := SerialNumber()
	if err != nil {
		t.Fatalf("SerialNumber() error = %v", err)
	}
}
