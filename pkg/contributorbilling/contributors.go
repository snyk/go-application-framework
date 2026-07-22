package contributorbilling

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// ListContributors scans the git log and returns the most recent commit timestamp
// per author email within [since, until], walking at most maxCommits from HEAD.
// Non-git paths, empty repos, and maxCommits <= 0 return nil contributors without error.
func ListContributors(path string, since, until time.Time, maxCommits int) ([]Contributor, error) {
	if maxCommits <= 0 {
		return nil, nil
	}

	repo, err := git.PlainOpenWithOptions(path, &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if errors.Is(err, git.ErrRepositoryNotExists) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open repository: %w", err)
	}

	head, err := repo.Head()
	if errors.Is(err, plumbing.ErrReferenceNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read head: %w", err)
	}

	iter, err := repo.Log(&git.LogOptions{
		From:  head.Hash(),
		Since: &since,
		Until: &until,
	})
	if err != nil {
		return nil, fmt.Errorf("read log: %w", err)
	}
	defer iter.Close()

	authors := make(map[string]time.Time)

	for i := 0; i < maxCommits; i++ {
		commit, err := iter.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read commit: %w", err)
		}

		email := commit.Author.Email
		when := commit.Author.When

		if prev, ok := authors[email]; ok && when.Before(prev) {
			continue
		}

		authors[email] = when
	}

	contributors := make([]Contributor, 0, len(authors))
	for email, lastCommitDate := range authors {
		contributors = append(contributors, Contributor{
			Email:            email,
			LatestCommitDate: lastCommitDate,
		})
	}

	sort.Slice(contributors, func(i, j int) bool {
		return contributors[i].Email < contributors[j].Email
	})

	return contributors, nil
}

func collectContributors(repoPath string, now time.Time) ([]Contributor, error) {
	since := now.AddDate(0, 0, -ContributingDeveloperPeriodDays)
	return ListContributors(repoPath, since, now, MaxCommitsInGitLog)
}
