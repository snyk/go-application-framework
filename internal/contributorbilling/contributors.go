package contributorbilling

import (
	"strings"
	"time"

	gitutil "github.com/snyk/go-application-framework/pkg/utils/git"
)

func collectContributors(repoPath string, now time.Time) ([]Contributor, error) {
	since := now.AddDate(0, 0, -ContributingDeveloperPeriodDays)
	authors, err := gitutil.ListContributors(repoPath, since, now, MaxCommitsInGitLog)
	if err != nil {
		return nil, err
	}

	contributors := make([]Contributor, len(authors))
	for i, author := range authors {
		contributors[i] = Contributor{
			Email:            author.Email,
			LatestCommitDate: author.LatestCommitDate,
		}
	}

	return contributors, nil
}

// dedupeContributorsByEmail collapses duplicate contributor emails in one emit payload,
// treating emails as case-insensitive and keeping the latest commit date per email.
func dedupeContributorsByEmail(contributors []Contributor) []Contributor {
	if len(contributors) <= 1 {
		return contributors
	}

	byEmail := make(map[string]Contributor)

	for _, contributor := range contributors {
		if contributor.Email == "" {
			continue
		}

		normalizedEmail := strings.ToLower(strings.TrimSpace(contributor.Email))
		existing, seen := byEmail[normalizedEmail]
		if !seen || contributor.LatestCommitDate.After(existing.LatestCommitDate) {
			byEmail[normalizedEmail] = contributor
		}
	}

	if len(byEmail) == 0 {
		return nil
	}

	deduped := make([]Contributor, len(byEmail))
	i := 0
	for _, c := range byEmail {
		deduped[i] = c
		i++
	}

	return deduped
}

func dedupeContributorsForItems(items []BillingItem) {
	for i := range items {
		if len(items[i].Contributors) == 0 {
			continue
		}
		items[i].Contributors = dedupeContributorsByEmail(items[i].Contributors)
	}
}
