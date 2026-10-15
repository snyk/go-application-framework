//go:build windows

package machineid

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

type renameCase struct {
	name string
	hold func(t *testing.T, path string) (*os.File, error)
}

func openHandle(t *testing.T, path string, access, share uint32) (*os.File, error) {
	t.Helper()
	name, err := syscall.UTF16PtrFromString(path)
	require.NoError(t, err)
	h, err := syscall.CreateFile(name, access, share, nil, syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func TestDiagnoseRenameOverHeldTarget(t *testing.T) {
	const (
		rw  = syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE
		rwd = rw | syscall.FILE_SHARE_DELETE
	)
	cases := []renameCase{
		{"no handle held", nil},
		{"reader GENERIC_READ share RW (old open)", func(t *testing.T, p string) (*os.File, error) {
			t.Helper()
			return openHandle(t, p, syscall.GENERIC_READ, rw)
		}},
		{"reader GENERIC_READ share RWD (new open)", func(t *testing.T, p string) (*os.File, error) {
			t.Helper()
			return openHandle(t, p, syscall.GENERIC_READ, rwd)
		}},
		{"holder GENERIC_READ|DELETE share RWD", func(t *testing.T, p string) (*os.File, error) {
			t.Helper()
			return openHandle(t, p, syscall.GENERIC_READ|deleteAccess, rwd)
		}},
		{"holder GENERIC_READ|DELETE share RW", func(t *testing.T, p string) (*os.File, error) {
			t.Helper()
			return openHandle(t, p, syscall.GENERIC_READ|deleteAccess, rw)
		}},
	}

	var matrix []string
	for _, c := range cases {
		dir := t.TempDir()
		target := filepath.Join(dir, "machine-id.json")
		require.NoError(t, os.WriteFile(target, []byte(""), 0o600))

		var held *os.File
		outcome := "ok"
		if c.hold != nil {
			f, err := c.hold(t, target)
			if err != nil {
				outcome = fmt.Sprintf("hold failed: %v", err)
			}
			held = f
		}
		if outcome == "ok" {
			tmp := filepath.Join(dir, ".machine-id-tmp")
			require.NoError(t, os.WriteFile(tmp, []byte(`{"machine_id":"new-id"}`), 0o600))
			if err := os.Rename(tmp, target); err != nil {
				var errno syscall.Errno
				if errors.As(err, &errno) {
					outcome = fmt.Sprintf("rename failed errno=%d (%v)", uint32(errno), err)
				} else {
					outcome = fmt.Sprintf("rename failed: %v", err)
				}
			}
		}
		if held != nil {
			_ = held.Close()
		}
		line := fmt.Sprintf("%-45s -> %s", c.name, outcome)
		t.Log(line)
		matrix = append(matrix, line)
	}
	t.Fatalf("rename-over-held-target matrix:\n%s", strings.Join(matrix, "\n"))
}
