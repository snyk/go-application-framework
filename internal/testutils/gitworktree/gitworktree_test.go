package gitworktree

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitWorktreeAdd_ignoresInheritedGitDir(t *testing.T) {
	decoyDir := NewMainRepo(t)
	mainDir := NewMainRepo(t)
	t.Setenv("GIT_DIR", filepath.Join(decoyDir, ".git"))

	worktreeDir := GitWorktreeAdd(t, mainDir)

	assert.DirExists(t, filepath.Join(mainDir, ".git", "worktrees", worktreeName))
	_, err := os.Stat(filepath.Join(decoyDir, ".git", "worktrees"))
	require.True(t, os.IsNotExist(err), "decoy repository must not gain a worktree")
	assert.FileExists(t, filepath.Join(worktreeDir, ".git"))
}
