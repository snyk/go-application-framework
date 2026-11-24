//go:build linux || darwin

package git

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openDescriptorsOf(t *testing.T, path string) []int {
	t.Helper()
	var target syscall.Stat_t
	require.NoError(t, syscall.Stat(path, &target))
	fdDir, err := os.Open("/dev/fd")
	require.NoError(t, err)
	names, err := fdDir.Readdirnames(-1)
	require.NoError(t, err)
	require.NoError(t, fdDir.Close())
	var open []int
	for _, name := range names {
		fd, err := strconv.Atoi(name)
		require.NoError(t, err)
		var st syscall.Stat_t
		err = syscall.Fstat(fd, &st)
		if errors.Is(err, syscall.EBADF) {
			continue
		}
		require.NoError(t, err)
		if st.Dev == target.Dev && st.Ino == target.Ino {
			open = append(open, fd)
		}
	}
	return open
}

func TestHeadCommitHashFromDir_LinkedWorktree_ReleasesFileHandles(t *testing.T) {
	dir, _, expected := initRepoWithCommit(t)
	worktreeDir := addLinkedWorktree(t, dir)
	commondir := filepath.Join(dir, ".git", "worktrees", filepath.Base(worktreeDir), "commondir")
	held, err := os.Open(commondir)
	require.NoError(t, err)
	require.Len(t, openDescriptorsOf(t, commondir), 1)
	require.NoError(t, held.Close())

	commitHash, err := HeadCommitHashFromDir(worktreeDir)

	require.NoError(t, err)
	assert.Equal(t, expected, commitHash)
	assert.Emptyf(t, openDescriptorsOf(t, commondir), "%s is still open", commondir)
}
