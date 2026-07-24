package contributorbilling_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/contributorbilling"
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

func initEmptyGitRepo(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	_, err := git.PlainInit(dir, false)
	require.NoError(t, err)
	return dir
}

func TestListContributors_KeepsMostRecentCommitPerEmail(t *testing.T) {
	t.Parallel()

	repoPath := initGitRepo(t,
		commitSpec{email: "alice@example.com", when: time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)},
		commitSpec{email: "alice@example.com", when: time.Date(2026, 1, 20, 10, 0, 0, 0, time.UTC)},
		commitSpec{email: "bob@example.com", when: time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)},
	)

	since := time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	contributors, err := contributorbilling.ListContributors(repoPath, since, until, contributorbilling.MaxCommitsInGitLog)
	require.NoError(t, err)
	require.Len(t, contributors, 2)

	assert.Equal(t, "alice@example.com", contributors[0].Email)
	assert.Equal(t, time.Date(2026, 1, 20, 10, 0, 0, 0, time.UTC), contributors[0].LatestCommitDate.UTC())
	assert.Equal(t, "bob@example.com", contributors[1].Email)
}

func TestListContributors_NonGitRepoReturnsEmpty(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	contributors, err := contributorbilling.ListContributors(dir, time.Now().AddDate(0, 0, -90), time.Now(), 500)
	require.NoError(t, err)
	assert.Empty(t, contributors)
}

func TestListContributors_EmptyRepoReturnsEmpty(t *testing.T) {
	t.Parallel()

	repoPath := initEmptyGitRepo(t)
	contributors, err := contributorbilling.ListContributors(
		repoPath,
		time.Now().AddDate(0, 0, -90),
		time.Now(),
		contributorbilling.MaxCommitsInGitLog,
	)
	require.NoError(t, err)
	assert.Empty(t, contributors)
}

func TestListContributors_MaxCommitsZeroReturnsEmpty(t *testing.T) {
	t.Parallel()

	repoPath := initGitRepo(t,
		commitSpec{email: "dev@example.com", when: time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)},
	)

	contributors, err := contributorbilling.ListContributors(
		repoPath,
		time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		0,
	)
	require.NoError(t, err)
	assert.Empty(t, contributors)
}

func TestListContributors_SortedByEmail(t *testing.T) {
	t.Parallel()

	repoPath := initGitRepo(t,
		commitSpec{email: "zed@example.com", when: time.Date(2026, 1, 10, 10, 0, 0, 0, time.UTC)},
		commitSpec{email: "amy@example.com", when: time.Date(2026, 1, 11, 10, 0, 0, 0, time.UTC)},
	)

	contributors, err := contributorbilling.ListContributors(
		repoPath,
		time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		contributorbilling.MaxCommitsInGitLog,
	)
	require.NoError(t, err)
	require.Len(t, contributors, 2)
	assert.Equal(t, "amy@example.com", contributors[0].Email)
	assert.Equal(t, "zed@example.com", contributors[1].Email)
}

func TestListContributors_RespectsMaxCommits(t *testing.T) {
	t.Parallel()

	commits := make([]commitSpec, 0, 10)
	for i := range 10 {
		commits = append(commits, commitSpec{
			email: "dev@example.com",
			when:  time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC),
		})
	}

	repoPath := initGitRepo(t, commits...)

	contributors, err := contributorbilling.ListContributors(
		repoPath,
		time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		3,
	)
	require.NoError(t, err)
	require.Len(t, contributors, 1)
	assert.Equal(t, time.Date(2026, 1, 1, 0, 0, 9, 0, time.UTC), contributors[0].LatestCommitDate.UTC())
}
