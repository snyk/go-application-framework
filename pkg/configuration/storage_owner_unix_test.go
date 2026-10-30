//go:build unix

package configuration

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ownedBy struct {
	fs.FileInfo
	uid, gid uint32
}

func (o ownedBy) Sys() any { return &syscall.Stat_t{Uid: o.uid, Gid: o.gid} }

type withoutOwner struct{ fs.FileInfo }

func (withoutOwner) Sys() any { return nil }

func Test_matchOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
	info, err := os.Stat(path)
	require.NoError(t, err)
	ownerOf := func(t *testing.T) int {
		t.Helper()
		current, statErr := os.Stat(path)
		require.NoError(t, statErr)
		stat, ok := current.Sys().(*syscall.Stat_t)
		require.True(t, ok)
		return int(stat.Uid)
	}

	t.Run("a file info without unix ownership changes nothing", func(t *testing.T) {
		matchOwner(path, withoutOwner{info})

		assert.Equal(t, os.Getuid(), ownerOf(t))
	})

	t.Run("an owner that cannot be set is ignored", func(t *testing.T) {
		other, expected := uint32(0), os.Getuid()
		if os.Geteuid() == 0 {
			// Root can give the file away, which is the sudo case this exists for.
			other, expected = 65534, 65534
		}

		matchOwner(path, ownedBy{FileInfo: info, uid: other, gid: other})

		assert.Equal(t, expected, ownerOf(t))
	})
}
