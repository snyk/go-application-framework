package contributors

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
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

	contributors, err := collectContributors(repo, now)
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

	contributors, err := collectContributors(repo, now)
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

	contributors, err := collectContributors(repo, now)
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

	contributors, err := collectContributors(repo, now)
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

	contributors, err := collectContributors(repo, now)
	require.NoError(t, err)
	assert.Equal(t, []string{"alice@example.com", "bob@example.com", "carol@example.com"}, emails(contributors))
}

func TestCollectContributors_ReturnsNothingForNonRepository(t *testing.T) {
	contributors, err := collectContributors(t.TempDir(), time.Now())
	require.NoError(t, err, "scanning a directory that is not a repository is normal, not an error")
	assert.Empty(t, contributors)
}

func TestCollectContributors_ReturnsNothingForRepositoryWithoutCommits(t *testing.T) {
	dir := t.TempDir()
	_, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	contributors, err := collectContributors(dir, time.Now())
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

	contributors, err := collectContributors(repo, now)
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

	contributors, err := collectContributors(repo, now)
	require.NoError(t, err)
	assert.Empty(t, contributors, "the committer-time early stop excludes this commit before its author date is checked")
}

func TestCollectContributors_ReturnsNothingForBareRepositoryWithoutCommits(t *testing.T) {
	dir := t.TempDir()
	_, err := git.PlainInit(dir, true)
	require.NoError(t, err)

	contributors, err := collectContributors(dir, time.Now())
	require.NoError(t, err)
	assert.Empty(t, contributors)
}

func TestCollectContributors_FindsRepositoryFromSubdirectory(t *testing.T) {
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	repo := newTestRepo(t, commit{email: "alice@example.com", when: now.AddDate(0, 0, -1)})

	nested := filepath.Join(repo, "pkg", "deep")
	require.NoError(t, os.MkdirAll(nested, 0o750))

	contributors, err := collectContributors(nested, now)
	require.NoError(t, err)
	require.Len(t, contributors, 1)
	assert.Equal(t, "alice@example.com", contributors[0].Email)
}

// commit describes one commit to create in a test repository.
type commit struct {
	name  string
	email string
	when  time.Time

	// branch defaults to main if zero. It is used to build a repo with
	// commits on multiple branches, that are not reachable from eachother.
	branch string

	// remote makes branch exist only as a remote-tracking ref, as if it
	// were never checked out locally.
	remote bool

	// committerWhen defaults to when if zero. It is used to explicitly build a
	// commit whose committer date is different from its author date, e.g. to
	// simulate a rebase or amend.
	committerWhen time.Time
}

// newTestRepo creates a git repository containing the given commits, in order,
// and returns its path.
func newTestRepo(t *testing.T, commits ...commit) string {
	t.Helper()

	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	worktree, err := repo.Worktree()
	require.NoError(t, err)

	_, err = worktree.Commit("base commit", &git.CommitOptions{
		AllowEmptyCommits: true,
		Author:            &object.Signature{Name: "base", Email: "base", When: time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)},
		Committer:         &object.Signature{Name: "base", Email: "base", When: time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)},
	})
	require.NoError(t, err)

	h, err := repo.Head()
	require.NoError(t, err)
	baseHash := h.Hash()

	const file = "log.txt"

	branches := map[string][]commit{}
	remoteBranches := map[string]bool{}
	for _, c := range commits {
		b := c.branch
		if b == "" {
			b = "main"
		}
		branches[b] = append(branches[b], c)
		if c.remote {
			remoteBranches[b] = true
		}
	}

	for b, cs := range branches {
		err = worktree.Checkout(&git.CheckoutOptions{Create: true, Hash: baseHash, Branch: plumbing.NewBranchReferenceName(b)})
		require.NoError(t, err, "expect target branch checkout to succeed")

		for i, c := range cs {
			require.NoError(t, os.WriteFile(filepath.Join(dir, file), fmt.Appendf(nil, "%d %s", i, c.email), 0o600))

			_, err = worktree.Add(file)
			require.NoError(t, err)

			name := c.name
			if name == "" {
				name = "Test Author"
			}

			committerWhen := c.committerWhen
			if committerWhen.IsZero() {
				committerWhen = c.when
			}

			_, err = worktree.Commit(fmt.Sprintf("commit %d", i), &git.CommitOptions{
				Author:    &object.Signature{Name: name, Email: c.email, When: c.when},
				Committer: &object.Signature{Name: name, Email: c.email, When: committerWhen},
			})
			require.NoError(t, err)
		}
	}

	for b := range remoteBranches {
		branchRef := plumbing.NewBranchReferenceName(b)
		ref, err := repo.Reference(branchRef, false)
		require.NoError(t, err)
		require.NoError(t, repo.Storer.SetReference(plumbing.NewHashReference(plumbing.NewRemoteReferenceName("origin", b), ref.Hash())))
		require.NoError(t, repo.Storer.RemoveReference(branchRef))
	}

	return dir
}
