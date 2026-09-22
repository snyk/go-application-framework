//go:build linux

package machineid

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadHardwareSerial_Linux_ReadsSysfsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "product_serial")
	require.NoError(t, os.WriteFile(path, []byte("5CG1234ABC\n"), 0o644))

	original := dmiProductSerialPath
	dmiProductSerialPath = path
	t.Cleanup(func() { dmiProductSerialPath = original })

	value, ok := readHardwareSerial(context.Background(), nil)
	require.True(t, ok)
	require.Equal(t, "5CG1234ABC\n", value, "trimming is readSerialCandidate's job, not the platform reader's")
}

func TestReadHardwareSerial_Linux_MissingFileIsAbsent(t *testing.T) {
	original := dmiProductSerialPath
	dmiProductSerialPath = filepath.Join(t.TempDir(), "does-not-exist")
	t.Cleanup(func() { dmiProductSerialPath = original })

	_, ok := readHardwareSerial(context.Background(), nil)
	require.False(t, ok)
}

func TestReadHardwareSerial_Linux_PermissionDeniedIsAbsent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file permission bits")
	}
	path := filepath.Join(t.TempDir(), "product_serial")
	require.NoError(t, os.WriteFile(path, []byte("5CG1234ABC"), 0o000))

	original := dmiProductSerialPath
	dmiProductSerialPath = path
	t.Cleanup(func() { dmiProductSerialPath = original })

	_, ok := readHardwareSerial(context.Background(), nil)
	require.False(t, ok)
}

// TestReadHardwareSerial_Linux_PlaceholderValueFallsThroughViaReadSerialCandidate proves the
// integration between the sysfs reader and validation: a manufacturer placeholder read from sysfs
// must not become the machine identifier.
func TestReadHardwareSerial_Linux_PlaceholderValueFallsThroughViaReadSerialCandidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "product_serial")
	require.NoError(t, os.WriteFile(path, []byte("Default string\n"), 0o644))

	original := dmiProductSerialPath
	dmiProductSerialPath = path
	t.Cleanup(func() { dmiProductSerialPath = original })

	require.Equal(t, "", readSerialCandidate(true, nil))
}
