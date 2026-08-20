package contributors

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCollectContributors_KeepsLatestCommitPerAuthor(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	older := now.AddDate(0, 0, -20)
	newer := now.AddDate(0, 0, -2)

	repo := newTestRepo(t,
		commit{email: "alice@example.com", when: older},
		commit{email: "alice@example.com", when: newer},
		commit{email: "bob@example.com", when: older},
	)

	contributors, err := collectContributors(t.Context(), repo.path(), now)
	require.NoError(t, err)
	require.Len(t, contributors, 2)

	assert.Equal(t, "alice@example.com", contributors[0].Email)
	assert.Equal(t, newer.UTC(), contributors[0].CommitDate.UTC())
	assert.Equal(t, "bob@example.com", contributors[1].Email)
	assert.Equal(t, older.UTC(), contributors[1].CommitDate.UTC())
}

func TestCollectContributors_IncludesCommitsFromAllBranches(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	repo := newTestRepo(t,
		commit{email: "alice@example.com", when: now, branch: "a"},
		commit{email: "bob@example.com", when: now, branch: "b"},
		commit{email: "chuck@example.com", when: now, branch: "c", remote: true},
	)

	contributors, err := collectContributors(t.Context(), repo.path(), now)
	require.NoError(t, err)
	require.Len(t, contributors, 3)

	assert.Equal(t, "alice@example.com", contributors[0].Email)
	assert.Equal(t, now.UTC(), contributors[0].CommitDate.UTC())
	assert.Equal(t, "bob@example.com", contributors[1].Email)
	assert.Equal(t, now.UTC(), contributors[1].CommitDate.UTC())
	assert.Equal(t, "chuck@example.com", contributors[2].Email)
	assert.Equal(t, now.UTC(), contributors[2].CommitDate.UTC())
}

func TestCollectContributors_DeduplicatesEmailsCaseInsensitively(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	repo := newTestRepo(t,
		commit{email: "Alice@Example.com", when: now.AddDate(0, 0, -10)},
		commit{email: "alice@example.com", when: now.AddDate(0, 0, -3)},
	)

	contributors, err := collectContributors(t.Context(), repo.path(), now)
	require.NoError(t, err)
	require.Len(t, contributors, 1, "one human must not be billed twice for a change in email casing")
	assert.Equal(t, now.AddDate(0, 0, -3).UTC(), contributors[0].CommitDate.UTC())
}

func TestCollectContributors_ExcludesCommitsOutsideTheWindow(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	repo := newTestRepo(t,
		commit{email: "ancient@example.com", when: now.AddDate(0, 0, -contributorWindowDays-1)},
		commit{email: "recent@example.com", when: now.AddDate(0, 0, -contributorWindowDays+1)},
		commit{email: "future@example.com", when: now.AddDate(0, 0, 1)},
	)

	contributors, err := collectContributors(t.Context(), repo.path(), now)
	require.NoError(t, err)
	require.Len(t, contributors, 1)
	assert.Equal(t, "recent@example.com", contributors[0].Email)
}

func TestCollectContributors_SortsByEmail(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	repo := newTestRepo(t,
		commit{email: "carol@example.com", when: now.AddDate(0, 0, -3)},
		commit{email: "alice@example.com", when: now.AddDate(0, 0, -2)},
		commit{email: "bob@example.com", when: now.AddDate(0, 0, -1)},
	)

	contributors, err := collectContributors(t.Context(), repo.path(), now)
	require.NoError(t, err)
	assert.Equal(t, []string{"alice@example.com", "bob@example.com", "carol@example.com"}, emails(contributors))
}

func TestCollectContributors_ReturnsNothingForNonRepository(t *testing.T) {
	contributors, err := collectContributors(t.Context(), t.TempDir(), time.Now())
	require.NoError(t, err, "scanning a directory that is not a repository is normal, not an error")
	assert.Empty(t, contributors)
}

func TestCollectContributors_ReturnsNothingForRepositoryWithoutCommits(t *testing.T) {
	repo := newEmptyTestRepo(t)

	contributors, err := collectContributors(t.Context(), repo.path(), time.Now())
	require.NoError(t, err)
	assert.Empty(t, contributors)
}

func TestCollectContributors_ExcludesAuthorDateOutsideWindowEvenWithRecentCommitterDate(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	repo := newTestRepo(t, commit{
		email:         "rebased@example.com",
		when:          now.AddDate(0, 0, -contributorWindowDays-1),
		committerWhen: now.AddDate(0, 0, -1),
	})

	contributors, err := collectContributors(t.Context(), repo.path(), now)
	require.NoError(t, err)
	assert.Empty(t, contributors, "the author-date filter must exclude this commit regardless of committer date")
}

func TestCollectContributors_ExcludesCommitWhoseCommitterDateEndsIterationButAuthorDateIsInWindow(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	repo := newTestRepo(t, commit{
		email:         "old-committer@example.com",
		when:          now.AddDate(0, 0, -5),
		committerWhen: now.AddDate(0, 0, -contributorWindowDays-1),
	})

	contributors, err := collectContributors(t.Context(), repo.path(), now)
	require.NoError(t, err)
	assert.Empty(t, contributors, "the committer-time early stop excludes this commit before its author date is checked")
}

func TestCollectContributors_ReturnsNothingForBareRepositoryWithoutCommits(t *testing.T) {
	repo := newEmptyTestRepo(t, "--bare")

	contributors, err := collectContributors(t.Context(), repo.path(), time.Now())
	require.NoError(t, err)
	assert.Empty(t, contributors)
}

func TestCollectContributors_FindsRepositoryFromSubdirectory(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	repo := newTestRepo(t, commit{email: "alice@example.com", when: now.AddDate(0, 0, -1)})

	nested := filepath.Join(repo.path(), "pkg", "deep")
	require.NoError(t, os.MkdirAll(nested, 0o750))

	contributors, err := collectContributors(t.Context(), nested, now)
	require.NoError(t, err)
	require.Len(t, contributors, 1)
	assert.Equal(t, "alice@example.com", contributors[0].Email)
}

func TestCollectContributors_IncludesCommitsReachableOnlyFromDetachedHead(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	repo := newTestRepo(t,
		commit{email: "alice@example.com", when: now.AddDate(0, 0, -3)},
		commit{email: "bob@example.com", when: now.AddDate(0, 0, -2)},
		commit{email: "carol@example.com", when: now.AddDate(0, 0, -1)},
	).detach().deleteBranch(testBranch)

	contributors, err := collectContributors(t.Context(), repo.path(), now)
	require.NoError(t, err)
	assert.Equal(t,
		[]string{"alice@example.com", "bob@example.com", "carol@example.com"},
		emails(contributors),
		"a detached checkout with no branch pointing at it must still be counted",
	)
}

func TestCollectContributors_ReadsShallowCloneToItsDepth(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	source := newTestRepo(t,
		commit{email: "alice@example.com", when: now.AddDate(0, 0, -3)},
		commit{email: "bob@example.com", when: now.AddDate(0, 0, -2)},
		commit{email: "carol@example.com", when: now.AddDate(0, 0, -1)},
	)

	tests := map[int][]string{
		1: {"carol@example.com"},
		2: {"bob@example.com", "carol@example.com"},
		3: {"alice@example.com", "bob@example.com", "carol@example.com"},
	}

	for depth, want := range tests {
		t.Run("depth "+strconv.Itoa(depth), func(t *testing.T) {
			clone := source.shallowClone(depth)

			contributors, err := collectContributors(t.Context(), clone.path(), now)
			require.NoError(t, err, "a truncated history must be readable, not a failure")
			assert.Equal(t, want, emails(contributors), "only the commits a shallow clone holds can be counted")
		})
	}
}

func TestCollectContributors_ReadsShallowDetachedClone(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	// How CI systems commonly check a repository out.
	repo := newTestRepo(t,
		commit{email: "alice@example.com", when: now.AddDate(0, 0, -2)},
		commit{email: "carol@example.com", when: now.AddDate(0, 0, -1)},
	).shallowClone(1).detach().deleteBranch(testBranch)

	contributors, err := collectContributors(t.Context(), repo.path(), now)
	require.NoError(t, err)
	assert.Equal(t, []string{"carol@example.com"}, emails(contributors))
}

func TestCollectContributors_IncludesCommitsFromLinkedWorktree(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	tests := map[string]func(*testRepo) *testRepo{
		"on a branch":        (*testRepo).worktree,
		"with detached head": (*testRepo).detachedWorktree,
	}

	for name, addWorktree := range tests {
		t.Run(name, func(t *testing.T) {
			source := newTestRepo(t,
				commit{email: "alice@example.com", when: now.AddDate(0, 0, -2)},
				commit{email: "carol@example.com", when: now.AddDate(0, 0, -1)},
			)

			contributors, err := collectContributors(t.Context(), addWorktree(source).path(), now)
			require.NoError(t, err)
			assert.Equal(t,
				[]string{"alice@example.com", "carol@example.com"},
				emails(contributors),
				"a worktree keeps its objects in the main repository, which must still be read",
			)
		})
	}
}

func TestCollectContributors_LeavesTheWorktreeItReadDeletable(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	source := newTestRepo(t, commit{email: "alice@example.com", when: now.AddDate(0, 0, -1)})
	worktree := source.worktree()

	_, err := collectContributors(t.Context(), worktree.path(), now)
	require.NoError(t, err)

	// Windows refuses to delete a file that is still open, so a handle left on
	// the worktree's commondir surfaces here.
	source.remove()
}

func TestCollectContributors_ReturnsNothingForWorktreeWithoutItsRepository(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	source := newTestRepo(t, commit{email: "alice@example.com", when: now.AddDate(0, 0, -1)})
	worktree := source.worktree()
	source.remove()

	contributors, err := collectContributors(t.Context(), worktree.path(), now)
	require.NoError(t, err, "an unusable repository is a contributor count of 0, not an error")
	assert.Empty(t, contributors)
}

func TestCollectContributors_ReturnsErrorForCancelledContext(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	repo := newTestRepo(t, commit{email: "alice@example.com", when: now.AddDate(0, 0, -1)})

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	contributors, err := collectContributors(ctx, repo.path(), now)
	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, contributors)
}

func TestCollectContributors_StopsWalkingWhenContextIsCancelled(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	repo := newTestRepo(t,
		commit{email: "alice@example.com", when: now.AddDate(0, 0, -1)},
		commit{email: "bob@example.com", when: now.AddDate(0, 0, -2)},
	)

	ctx := &canceledOnErrCheck{cancelFrom: 2}

	contributors, err := collectContributors(ctx, repo.path(), now)
	require.ErrorIs(t, err, context.Canceled, "cancellation during the commit walk must abort it")
	assert.Empty(t, contributors, "a canceled walk must not report the contributors it found so far")
	assert.Less(t, ctx.checks, 3, "the walk must stop on the first canceled commit, not keep going")
}

// canceledOnErrCheck is a context that reports itself canceled when calls
// to Err == cancelFrom and onwards.
type canceledOnErrCheck struct {
	cancelFrom int
	checks     int
}

func (c *canceledOnErrCheck) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *canceledOnErrCheck) Done() <-chan struct{}       { return nil }
func (c *canceledOnErrCheck) Value(any) any               { return nil }

func (c *canceledOnErrCheck) Err() error {
	c.checks++
	if c.checks >= c.cancelFrom {
		return context.Canceled
	}
	return nil
}
