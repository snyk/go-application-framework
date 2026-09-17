package contributors

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
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
	require.ErrorIs(t, err, ErrNotAGitRepository, "scanning a directory that is not a repository is normal, but callers must be able to tell")
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

func TestCollectContributors_ReportsBareRepositoryAsNoRepository(t *testing.T) {
	repo := newEmptyTestRepo(t, "--bare")

	// Detecting a repository by its .git directory, which is how a scan target is
	// resolved, finds nothing in a bare repository. We have never read one.
	contributors, err := collectContributors(t.Context(), repo.path(), time.Now())
	require.ErrorIs(t, err, ErrNotAGitRepository)
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

// git permits these extensions while core.repositoryFormatVersion is 0, so a
// repository declaring one has to stay readable. Azure Pipelines enables
// worktreeConfig on every checkout, and go-git rejects all three.
func TestCollectContributors_ReadsRepoDeclaringExtensionPermittedAtFormatVersion0(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	tests := map[string]string{
		"extensions.worktreeConfig":  "true",
		"extensions.partialClone":    "origin",
		"extensions.preciousObjects": "true",
	}

	for key, value := range tests {
		t.Run(key, func(t *testing.T) {
			repo := newTestRepo(t,
				commit{email: "alice@example.com", when: now.AddDate(0, 0, -1)},
			).withConfig(key, value)

			contributors, err := collectContributors(t.Context(), repo.path(), now)
			require.NoError(t, err, "an extension go-git does not recognize must not stop the repository being read")
			assert.Equal(t, []string{"alice@example.com"}, emails(contributors))
		})
	}
}

func TestCollectContributors_ReadsAzurePipelinesCheckout(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	repo := newTestRepo(t,
		commit{email: "alice@example.com", when: now.AddDate(0, 0, -2)},
		commit{email: "carol@example.com", when: now.AddDate(0, 0, -1)},
	).azurePipelinesCheckout()

	contributors, err := collectContributors(t.Context(), repo.path(), now)
	require.NoError(t, err)
	assert.Equal(t, []string{"carol@example.com"}, emails(contributors), "depth 1 holds only the checked out commit")
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
	require.ErrorIs(t, err, ErrNotAGitRepository, "a worktree cut off from its objects reads as no repository at all")
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

func TestDetectGitDir(t *testing.T) {
	t.Parallel()

	t.Run("repository root", func(t *testing.T) {
		t.Parallel()

		repo := newEmptyTestRepo(t)

		gitDir, worktreeRoot, err := detectGitDir(repo.path())
		require.NoError(t, err)
		assertSamePath(t, filepath.Join(repo.path(), ".git"), gitDir)
		assertSamePath(t, repo.path(), worktreeRoot)
	})

	t.Run("directory below the repository root", func(t *testing.T) {
		t.Parallel()

		repo := newEmptyTestRepo(t)
		nested := filepath.Join(repo.path(), "pkg", "deep")
		require.NoError(t, os.MkdirAll(nested, 0o750))

		gitDir, worktreeRoot, err := detectGitDir(nested)
		require.NoError(t, err)
		assertSamePath(t, filepath.Join(repo.path(), ".git"), gitDir)
		assertSamePath(t, repo.path(), worktreeRoot, "the worktree root is the repository, not the directory scanned")
	})

	t.Run("linked worktree", func(t *testing.T) {
		t.Parallel()

		now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
		worktree := newTestRepo(t, commit{email: "alice@example.com", when: now}).worktree()

		gitDir, worktreeRoot, err := detectGitDir(worktree.path())
		require.NoError(t, err)
		assertSamePath(t, worktree.git("rev-parse", "--absolute-git-dir"), gitDir)
		assertSamePath(t, worktree.path(), worktreeRoot)
	})

	t.Run("directory below a linked worktree", func(t *testing.T) {
		t.Parallel()

		now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
		worktree := newTestRepo(t, commit{email: "alice@example.com", when: now}).worktree()
		nested := filepath.Join(worktree.path(), "pkg")
		require.NoError(t, os.MkdirAll(nested, 0o750))

		gitDir, worktreeRoot, err := detectGitDir(nested)
		require.NoError(t, err)
		assertSamePath(t, worktree.git("rev-parse", "--absolute-git-dir"), gitDir)
		assertSamePath(t, worktree.path(), worktreeRoot)
	})

	t.Run("bare repository", func(t *testing.T) {
		t.Parallel()

		repo := newEmptyTestRepo(t, "--bare")

		gitDir, worktreeRoot, err := detectGitDir(repo.path())
		require.NoError(t, err)
		assertSamePath(t, repo.path(), gitDir, "a bare repository is its own git directory")
		assert.Empty(t, worktreeRoot, "a bare repository has no worktree")
	})

	t.Run("git file pointing at a relative path", func(t *testing.T) {
		t.Parallel()

		root := t.TempDir()
		target := filepath.Join(root, "modules", "sub")
		require.NoError(t, os.MkdirAll(target, 0o750))
		worktree := filepath.Join(root, "sub")
		require.NoError(t, os.MkdirAll(worktree, 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: ../modules/sub\n"), 0o600))

		gitDir, worktreeRoot, err := detectGitDir(worktree)
		require.NoError(t, err)
		assertSamePath(t, target, gitDir)
		assertSamePath(t, worktree, worktreeRoot)
	})

	t.Run("git file with no target", func(t *testing.T) {
		t.Parallel()

		worktree := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir:\n"), 0o600))

		_, _, err := detectGitDir(worktree)
		require.ErrorIs(t, err, git.ErrRepositoryNotExists)
	})

	t.Run("directory that is not in a repository", func(t *testing.T) {
		t.Parallel()

		_, _, err := detectGitDir(t.TempDir())
		require.ErrorIs(t, err, git.ErrRepositoryNotExists, "the walk up must end at the filesystem root rather than looping")
	})

	t.Run("directory that does not exist", func(t *testing.T) {
		t.Parallel()

		_, _, err := detectGitDir(filepath.Join(t.TempDir(), "gone"))
		require.ErrorIs(t, err, git.ErrRepositoryNotExists)
	})
}

// TestDetectGitDir_ResolvesAPathRelativeToTheWorkingDirectory belongs to the
// suite above, but t.Chdir cannot be used in a parallel test.
func TestDetectGitDir_ResolvesAPathRelativeToTheWorkingDirectory(t *testing.T) {
	repo := newEmptyTestRepo(t)
	nested := filepath.Join(repo.path(), "pkg")
	require.NoError(t, os.MkdirAll(nested, 0o750))
	t.Chdir(repo.path())

	gitDir, worktreeRoot, err := detectGitDir("pkg")
	require.NoError(t, err)
	assertSamePath(t, filepath.Join(repo.path(), ".git"), gitDir)
	assertSamePath(t, repo.path(), worktreeRoot)
}

// assertSamePath asserts that two paths lead to the same directory, comparing
// what they point at rather than how they are spelled, since a temporary
// directory is reached through a symlink on some platforms.
func assertSamePath(t *testing.T, want, got string, msgAndArgs ...any) {
	t.Helper()

	wantInfo, err := os.Stat(want)
	require.NoError(t, err)
	gotInfo, err := os.Stat(got)
	require.NoErrorf(t, err, "detected path must exist: %s", got)

	if !os.SameFile(wantInfo, gotInfo) {
		assert.Fail(t, fmt.Sprintf("paths differ: want %s, got %s", want, got), msgAndArgs...)
	}
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
