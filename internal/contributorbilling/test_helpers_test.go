package contributorbilling_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/require"
)

type commitSpec struct {
	email string
	when  time.Time
}

func initGitRepo(t *testing.T, commits ...commitSpec) string {
	t.Helper()

	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	wt, err := repo.Worktree()
	require.NoError(t, err)

	filePath := filepath.Join(dir, "README.md")
	require.NoError(t, os.WriteFile(filePath, []byte("hello"), 0o600))

	for _, commit := range commits {
		_, err = wt.Add("README.md")
		require.NoError(t, err)

		_, err = wt.Commit("test commit", &git.CommitOptions{
			Author: &object.Signature{
				Name:  "Test User",
				Email: commit.email,
				When:  commit.when,
			},
			AllowEmptyCommits: true,
		})
		require.NoError(t, err)
	}

	return dir
}
