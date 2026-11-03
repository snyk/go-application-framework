// Package gitworktree builds git repositories with linked worktrees for tests.
package gitworktree

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

const (
	OriginURL    = "https://github.com/example/repo.git"
	BranchName   = "feature"
	worktreeName = "wt"
)

// NewMainRepo creates a repository with one commit on BranchName, an origin remote and no worktrees.
func NewMainRepo(t *testing.T) string {
	t.Helper()
	mainDir := NewMainRepoWithoutOrigin(t)
	repo, err := git.PlainOpen(mainDir)
	require.NoError(t, err)
	_, err = repo.CreateRemote(&config.RemoteConfig{Name: "origin", URLs: []string{OriginURL}})
	require.NoError(t, err)
	return mainDir
}

// NewMainRepoWithoutOrigin creates a repository with one commit on BranchName and no remotes.
func NewMainRepoWithoutOrigin(t *testing.T) string {
	t.Helper()
	mainDir := t.TempDir()
	repo, err := git.PlainInit(mainDir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(mainDir, "README.md"), []byte("readme"), 0o600))
	_, err = wt.Add("README.md")
	require.NoError(t, err)
	hash, err := wt.Commit("initial commit", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	})
	require.NoError(t, err)
	require.NoError(t, repo.Storer.SetReference(plumbing.NewHashReference(plumbing.NewBranchReferenceName(BranchName), hash)))

	return mainDir
}

// StageInWorktreeIndex adds files to the index of the linked worktree at worktreeDir, which lives in its private gitdir.
func StageInWorktreeIndex(t *testing.T, worktreeDir string, files ...string) {
	t.Helper()
	repo, err := git.PlainOpenWithOptions(worktreeDir, &git.PlainOpenOptions{
		DetectDotGit:          true,
		EnableDotGitCommonDir: true,
	})
	require.NoError(t, err)
	wt, err := repo.Worktree()
	require.NoError(t, err)
	for _, file := range files {
		_, err = wt.Add(file)
		require.NoError(t, err)
	}
}

// SetCommonDir overwrites the commondir file of the worktree private dir in mainDir.
func SetCommonDir(t *testing.T, mainDir string, value string) {
	t.Helper()
	privateDir := filepath.Join(mainDir, ".git", "worktrees", worktreeName)
	require.NoError(t, os.WriteFile(filepath.Join(privateDir, "commondir"), []byte(value), 0o600))
}

// NewHandBuiltWorktreeRelative is NewHandBuiltWorktree with a relative gitdir pointer, as git writes when the worktree sits under the main repo.
func NewHandBuiltWorktreeRelative(t *testing.T, mainDir string) string {
	t.Helper()
	worktreeDir := NewHandBuiltWorktree(t, mainDir)
	privateDir := filepath.Join(mainDir, ".git", "worktrees", worktreeName)
	rel, err := filepath.Rel(worktreeDir, privateDir)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(worktreeDir, ".git"), []byte("gitdir: "+rel+"\n"), 0o600))
	return worktreeDir
}

// GitWorktreeAdd creates a linked worktree on BranchName with the git binary, so the layout is the one git writes.
func GitWorktreeAdd(t *testing.T, mainDir string) string {
	t.Helper()
	worktreeDir := filepath.Join(t.TempDir(), worktreeName)
	cmd := exec.Command("git", "worktree", "add", worktreeDir, BranchName)
	cmd.Dir = mainDir
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "git worktree add: %s", out)
	return worktreeDir
}

// DetachHead rewrites the worktree's private HEAD to a bare commit hash, as git does after a detached checkout.
func DetachHead(t *testing.T, mainDir string) {
	t.Helper()
	repo, err := git.PlainOpen(mainDir)
	require.NoError(t, err)
	head, err := repo.Head()
	require.NoError(t, err)
	privateDir := filepath.Join(mainDir, ".git", "worktrees", worktreeName)
	require.NoError(t, os.WriteFile(filepath.Join(privateDir, "HEAD"), []byte(head.Hash().String()+"\n"), 0o600))
}

// NewHandBuiltWorktree lays out a linked worktree by writing the files git writes for one,
// without running the git binary. It returns the worktree directory.
func NewHandBuiltWorktree(t *testing.T, mainDir string) string {
	t.Helper()
	privateDir := filepath.Join(mainDir, ".git", "worktrees", worktreeName)
	require.NoError(t, os.MkdirAll(privateDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(privateDir, "HEAD"), []byte("ref: refs/heads/"+BranchName+"\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(privateDir, "commondir"), []byte("../..\n"), 0o600))

	worktreeDir := filepath.Join(t.TempDir(), worktreeName)
	require.NoError(t, os.MkdirAll(worktreeDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(worktreeDir, ".git"), []byte("gitdir: "+privateDir+"\n"), 0o600))

	return worktreeDir
}
