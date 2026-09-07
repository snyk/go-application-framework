package contributors

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
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
	"github.com/go-git/go-git/v5/storage"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/go-git/go-git/v5/storage/filesystem/dotgit"

	"github.com/snyk/go-application-framework/internal/apiclients/contributors_ingest"
)

// contributorWindowDays is the trailing period a commit must fall in to count
// its author as an active contributor.
const contributorWindowDays = 90

// collectContributors returns the git authors who committed to the repository at
// path within the contributor window ending at now, one entry per author holding
// their most recent commits authored date. All branches, including remotes, are
// iterated over, as is HEAD.
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
// A path that is not a git repository yields [ErrNotAGitRepository].
func collectContributors(ctx context.Context, path string, now time.Time) ([]contributors_ingest.Contributor, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	repo, closeRepo, err := openRepositoryFast(path)
	if errors.Is(err, git.ErrRepositoryNotExists) {
		return nil, ErrNotAGitRepository
	}
	if err != nil {
		return nil, fmt.Errorf("open repository: %w", err)
	}
	defer func() {
		_ = closeRepo() //nolint:errcheck // nothing to do on close failure
	}()

	shallow, err := repo.Storer.Shallow()
	if err != nil {
		return nil, fmt.Errorf("read shallow commits: %w", err)
	}
	roots, err := walkRoots(repo)
	if err != nil {
		return nil, err
	}
	unreachable := parentsOfShallow(repo.Storer, shallow)

	since := now.AddDate(0, 0, -contributorWindowDays)
	seen := make(map[plumbing.Hash]bool)
	latest := make(map[string]contributors_ingest.Contributor)
	for _, root := range roots {
		tip, commitErr := object.GetCommit(repo.Storer, root)
		if commitErr != nil {
			continue // ignore roots that don't resolve to a commit
		}

		err = object.NewCommitIterCTime(tip, seen, unreachable).ForEach(func(commit *object.Commit) error {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}

			seen[commit.Hash] = true

			if commit.Committer.When.Before(since) {
				return storer.ErrStop
			}

			recordAuthor(latest, commit, since, now)
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("read commits: %w", err)
		}
	}

	contributors := slices.Collect(maps.Values(latest))
	slices.SortFunc(contributors, func(a, b contributors_ingest.Contributor) int {
		return strings.Compare(a.Email, b.Email)
	})
	return contributors, nil
}

// walkRoots returns the commits to walk the history back from. HEAD is included
// because a detached checkout, which is how CI systems commonly check a
// repository out, has no branch pointing at its commits.
func walkRoots(repo *git.Repository) ([]plumbing.Hash, error) {
	var roots []plumbing.Hash
	if head, err := repo.Head(); err == nil {
		roots = append(roots, head.Hash())
	}

	refs, err := repo.References()
	if err != nil {
		return nil, fmt.Errorf("read references: %w", err)
	}
	defer refs.Close()

	err = refs.ForEach(func(ref *plumbing.Reference) error {
		if name := ref.Name(); name.IsBranch() || name.IsRemote() {
			roots = append(roots, ref.Hash())
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read references: %w", err)
	}

	return roots, nil
}

// parentsOfShallow returns the parents of the given shallow boundary commits,
// which a shallow clone did not download. The commit walker loads every parent
// before yielding a commit and fails on the first one that is absent, so these
// have to be excluded up front for a shallow repository to be readable at all.
func parentsOfShallow(store storage.Storer, shallow []plumbing.Hash) []plumbing.Hash {
	var parents []plumbing.Hash
	for _, hash := range shallow {
		commit, err := object.GetCommit(store, hash)
		if err != nil {
			continue // a boundary commit we cannot read has no parents to exclude
		}
		parents = append(parents, commit.ParentHashes...)
	}
	return parents
}

func recordAuthor(latest map[string]contributors_ingest.Contributor, commit *object.Commit, since, now time.Time) {
	email := strings.ToLower(strings.TrimSpace(commit.Author.Email))
	when := commit.Author.When

	if email == "" || when.Before(since) || when.After(now) {
		return
	}

	if existing, ok := latest[email]; ok && !when.After(existing.CommitDate) {
		return
	}
	latest[email] = contributors_ingest.Contributor{Email: email, CommitDate: when}
}

// openRepositoryFast opens the git repository at path the same way
// git.PlainOpenWithOptions(path, &git.PlainOpenOptions{DetectDotGit: true}) does,
// but reopens the result on go-git's BoundOS filesystem with a kept-open packfile
// descriptor to avoid reopening the packfile for every object read.
//
// A linked worktree, whose own git directory holds neither objects nor refs, is
// read through the common directory of the repository it belongs to.
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
		return repo, noopClose, nil //nolint:nilerr // err always git.ErrIsBareRepository at time of writing, but fallback
	default:
		wtFs = osfs.New(wt.Filesystem.Root(), osfs.WithBoundOS())
	}

	st := filesystem.NewStorageWithOptions(repositoryFilesystem(gitDir), cache.NewObjectLRUDefault(), filesystem.Options{KeepDescriptors: true})

	fast, err := git.Open(st, wtFs)
	if err != nil {
		_ = st.Close()
		return repo, noopClose, nil //nolint:nilerr // use the slow repo if our fast open fails
	}
	return fast, st.Close, nil
}

// repositoryFilesystem returns the filesystem holding the objects and refs of
// the git directory at gitDir.
//
// go-git resolves a linked worktree's common directory itself, but leaks the
// open commondir file when it does, which on Windows leaves the scanned
// repository locked. So the directories are wired up here instead.
func repositoryFilesystem(gitDir string) billy.Filesystem {
	commonDir := commonDirOf(gitDir)
	if commonDir == "" {
		return osfs.New(gitDir, osfs.WithBoundOS())
	}

	// Chroot filesystems rather than bound ones: the packfile reader reopens a
	// pack by the name its file reports, and only a chroot reports the relative
	// name that routing between these two directories needs.
	return dotgit.NewRepositoryFilesystem(osfs.New(gitDir), osfs.New(commonDir))
}

// commonDirOf returns the git directory holding the objects and refs of the
// linked worktree at gitDir, or empty if it is not a linked worktree.
func commonDirOf(gitDir string) string {
	content, err := os.ReadFile(filepath.Join(gitDir, "commondir")) //nolint:gosec // path derived from the repository we just opened
	if err != nil {
		return ""
	}

	commonDir := strings.TrimSpace(string(content))
	if commonDir == "" {
		return ""
	}
	if !filepath.IsAbs(commonDir) {
		commonDir = filepath.Join(gitDir, commonDir)
	}
	if _, err := os.Stat(commonDir); err != nil {
		return ""
	}
	return commonDir
}
