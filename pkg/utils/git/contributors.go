package git

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// AuthorLatestCommit holds one git author email and their most recent commit in the scan window.
type AuthorLatestCommit struct {
	Email            string
	LatestCommitDate time.Time
}

// ListContributors scans the git log and returns the most recent commit timestamp
// per author email within [since, until], walking at most maxCommits from HEAD.
// Non-git paths, empty repos, and maxCommits <= 0 return nil results without error.
func ListContributors(path string, since, until time.Time, maxCommits int) ([]AuthorLatestCommit, error) {
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
		From: head.Hash(),
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

		when := commit.Author.When
		if when.Before(since) {
			break
		}
		if when.After(until) {
			continue
		}

		email := commit.Author.Email
		if prev, ok := authors[email]; ok && when.Before(prev) {
			continue
		}

		authors[email] = when
	}

	results := make([]AuthorLatestCommit, 0, len(authors))
	for email, lastCommitDate := range authors {
		results = append(results, AuthorLatestCommit{
			Email:            email,
			LatestCommitDate: lastCommitDate,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Email < results[j].Email
	})

	return results, nil
}
