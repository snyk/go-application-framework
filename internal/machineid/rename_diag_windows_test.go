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

	"github.com/snyk/go-application-framework/internal/fileperms"
)

type renameCase struct {
	name     string
	readOnly bool
	hold     func(t *testing.T, path string) (*os.File, error)
	replace  func(t *testing.T, target string) (string, error)
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

func plainRename(t *testing.T, target string) (string, error) {
	t.Helper()
	tmp := filepath.Join(filepath.Dir(target), ".machine-id-tmp")
	require.NoError(t, os.WriteFile(tmp, []byte(`{"machine_id":"new-id"}`), 0o600))
	return "", os.Rename(tmp, target)
}

func productionWriteAt(t *testing.T, target string) (string, error) {
	t.Helper()
	return writeAt(target, "machine", fileperms.FILEPERM_644, "new-id", "generated", "diagnostic")
}

func attributesOf(t *testing.T, path string) (uint32, error) {
	t.Helper()
	name, err := syscall.UTF16PtrFromString(path)
	require.NoError(t, err)
	return syscall.GetFileAttributes(name)
}

func TestDiagnoseRenameOverHeldTarget(t *testing.T) {
	const (
		rw  = syscall.FILE_SHARE_READ | syscall.FILE_SHARE_WRITE
		rwd = rw | syscall.FILE_SHARE_DELETE
	)
	cases := []renameCase{
		{name: "plain rename, no handle held", replace: plainRename},
		{name: "plain rename, reader GENERIC_READ share RW", replace: plainRename,
			hold: func(t *testing.T, p string) (*os.File, error) {
				t.Helper()
				return openHandle(t, p, syscall.GENERIC_READ, rw)
			}},
		{name: "plain rename, reader GENERIC_READ share RWD", replace: plainRename,
			hold: func(t *testing.T, p string) (*os.File, error) {
				t.Helper()
				return openHandle(t, p, syscall.GENERIC_READ, rwd)
			}},
		{name: "plain rename, holder GENERIC_READ|DELETE share RWD", replace: plainRename,
			hold: func(t *testing.T, p string) (*os.File, error) {
				t.Helper()
				return openHandle(t, p, syscall.GENERIC_READ|deleteAccess, rwd)
			}},
		{name: "plain rename, holder GENERIC_READ|DELETE share RW", replace: plainRename,
			hold: func(t *testing.T, p string) (*os.File, error) {
				t.Helper()
				return openHandle(t, p, syscall.GENERIC_READ|deleteAccess, rw)
			}},
		{name: "plain rename, target READONLY, no handle held", readOnly: true, replace: plainRename},
		{name: "plain rename, target READONLY, reader share RWD", readOnly: true, replace: plainRename,
			hold: func(t *testing.T, p string) (*os.File, error) {
				t.Helper()
				return openHandle(t, p, syscall.GENERIC_READ, rwd)
			}},
		{name: "writeAt, seeded 0600, no handle held", replace: productionWriteAt},
		{name: "writeAt, seeded 0600, openIDFile reader held", replace: productionWriteAt,
			hold: func(t *testing.T, p string) (*os.File, error) {
				t.Helper()
				return openIDFile(p)
			}},
	}

	var matrix []string
	for _, c := range cases {
		dir := t.TempDir()
		target := filepath.Join(dir, "machine-id.json")
		require.NoError(t, os.WriteFile(target, []byte(""), 0o600))
		if c.readOnly {
			name, err := syscall.UTF16PtrFromString(target)
			require.NoError(t, err)
			require.NoError(t, syscall.SetFileAttributes(name, syscall.FILE_ATTRIBUTE_READONLY))
			t.Cleanup(func() { require.NoError(t, syscall.SetFileAttributes(name, syscall.FILE_ATTRIBUTE_NORMAL)) })
		}

		var held *os.File
		outcome := ""
		if c.hold != nil {
			f, err := c.hold(t, target)
			if err != nil {
				outcome = fmt.Sprintf("hold failed: %v", err)
			}
			held = f
		}
		attrs, attrErr := attributesOf(t, target)
		attrText := fmt.Sprintf("0x%x", attrs)
		if attrErr != nil {
			attrText = fmt.Sprintf("err(%v)", attrErr)
		}
		if outcome == "" {
			detail, err := c.replace(t, target)
			switch {
			case err == nil:
				outcome = "ok " + detail
			case errors.As(err, new(syscall.Errno)):
				var errno syscall.Errno
				errors.As(err, &errno)
				outcome = fmt.Sprintf("failed errno=%d (%v)", uint32(errno), err)
			default:
				outcome = fmt.Sprintf("failed: %v", err)
			}
		}
		if held != nil {
			_ = held.Close()
		}
		line := fmt.Sprintf("%-55s attrs_before=%s -> %s", c.name, attrText, outcome)
		t.Log(line)
		matrix = append(matrix, line)
	}
	t.Fatalf("rename-over-held-target matrix:\n%s", strings.Join(matrix, "\n"))
}
