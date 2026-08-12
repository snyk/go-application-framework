package contributors

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/storage/filesystem"

	"github.com/snyk/go-application-framework/internal/apiclients/contributors_ingest"
)

// contributorWindowDays is the trailing period a commit must fall in to count
// its author as an active contributor.
const contributorWindowDays = 90

// collectContributors returns the git authors who committed to the repository at
// path within the contributor window ending at now, one entry per author holding
// their most recent commits authored date. All branches, including remotes, are
// iterated over.
//
// Commits are iterated over using commit date, and the assumption is made that
// commit date >= authored date, which means a cutoff for commit date contains all
// our potential commits with an authored date in the window. Additionally, commits
// with authored dates in the future are excluded, because these are obviously
// incorrect and so including them risks over-counting.
//
// Authors are case-insensitively deduplicated and reported in lowercase.Results
// are sorted by email so payloads are stable.
//
// A path that is not a git repository, or a repository with no commits, yields no
// contributors and no error, because we proceed with a contributor count of 0.
func collectContributors(path string, now time.Time) ([]contributors_ingest.Contributor, error) {
	repo, closeRepo, err := openRepositoryFast(path)
	if errors.Is(err, git.ErrRepositoryNotExists) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open repository: %w", err)
	}
	defer func() {
		_ = closeRepo() //nolint:errcheck // nothing to do on close failure
	}()

	since := now.AddDate(0, 0, -contributorWindowDays)

	refs, err := repo.References()
	if err != nil {
		return nil, fmt.Errorf("read references: %w", err)
	}
	defer refs.Close()

	seen := make(map[plumbing.Hash]bool)
	latest := make(map[string]contributors_ingest.Contributor)
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		name := ref.Name()
		if !name.IsBranch() && !name.IsRemote() {
			return nil
		}

		tip, commitErr := object.GetCommit(repo.Storer, ref.Hash())
		if commitErr != nil {
			return nil //nolint:nilerr // ingore refs that don't resolve to a commit
		}

		return object.NewCommitIterCTime(tip, seen, nil).ForEach(func(commit *object.Commit) error {
			seen[commit.Hash] = true

			if commit.Committer.When.Before(since) {
				return storer.ErrStop
			}

			email := strings.ToLower(strings.TrimSpace(commit.Author.Email))
			when := commit.Author.When

			if email == "" || when.Before(since) || when.After(now) {
				return nil
			}

			if existing, ok := latest[email]; ok && !when.After(existing.CommitDate) {
				return nil
			}
			latest[email] = contributors_ingest.Contributor{Email: email, CommitDate: when}
			return nil
		})
	})
	if err != nil {
		return nil, fmt.Errorf("read commits: %w", err)
	}

	contributors := slices.Collect(maps.Values(latest))
	slices.SortFunc(contributors, func(a, b contributors_ingest.Contributor) int {
		return strings.Compare(a.Email, b.Email)
	})
	return contributors, nil
}

// openRepositoryFast opens the git repository at path the same way
// git.PlainOpenWithOptions(path, &git.PlainOpenOptions{DetectDotGit: true}) does,
// but reopens the result on go-git's BoundOS filesystem with a kept-open packfile
// descriptor to avoid reopening the packfile for every object read.
//
// Callers must call the returned close func once done with the repository.
func openRepositoryFast(path string) (*git.Repository, func() error, error) {
	noopClose := func() error { return nil }

	repo, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, noopClose, err
	}

	fsStorage, ok := repo.Storer.(*filesystem.Storage)
	if !ok {
		return repo, noopClose, nil
	}
	gitDir := fsStorage.Filesystem().Root()

	var wtFs billy.Filesystem
	wt, err := repo.Worktree()
	switch {
	case errors.Is(err, git.ErrIsBareRepository):
		// no worktree
	case err != nil:
		return repo, noopClose, nil //nolint:nilerr // worktree is invalid, assume no worktree
	default:
		wtFs = osfs.New(wt.Filesystem.Root(), osfs.WithBoundOS())
	}

	fs := osfs.New(gitDir, osfs.WithBoundOS())
	st := filesystem.NewStorageWithOptions(fs, cache.NewObjectLRUDefault(), filesystem.Options{KeepDescriptors: true})

	fast, err := git.Open(st, wtFs)
	if err != nil {
		_ = st.Close()
		return repo, noopClose, nil //nolint:nilerr // use the slow repo if our fast open fails
	}
	return fast, st.Close, nil
}
