//go:build windows

package git

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHeadCommitHashFromDir_LinkedWorktree_ReleasesFileHandles(t *testing.T) {
	dir, _, expected := initRepoWithCommit(t)
	worktreeDir := addLinkedWorktree(t, dir)
	commondir := filepath.Join(dir, ".git", "worktrees", filepath.Base(worktreeDir), "commondir")
	held, err := os.Open(commondir)
	require.NoError(t, err)
	require.Error(t, os.Remove(commondir))
	require.NoError(t, held.Close())

	commitHash, err := HeadCommitHashFromDir(worktreeDir)

	require.NoError(t, err)
	assert.Equal(t, expected, commitHash)
	require.NoError(t, os.Remove(commondir))
}
