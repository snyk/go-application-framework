//go:build linux

package git

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openFilesUnder(t *testing.T, dir string) []string {
	t.Helper()
	fdDir := "/proc/self/fd"
	entries, err := os.ReadDir(fdDir)
	require.NoError(t, err)
	resolvedDir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	var open []string
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, entry.Name()))
		if err == nil && strings.HasPrefix(target, resolvedDir+string(filepath.Separator)) {
			open = append(open, target)
		}
	}
	return open
}

func TestHeadCommitHashFromDir_LinkedWorktree_ReleasesFileHandles(t *testing.T) {
	dir, _, expected := initRepoWithCommit(t)
	worktreeDir := addLinkedWorktree(t, dir)

	commitHash, err := HeadCommitHashFromDir(worktreeDir)

	require.NoError(t, err)
	assert.Equal(t, expected, commitHash)
	assert.Empty(t, openFilesUnder(t, dir))
}
