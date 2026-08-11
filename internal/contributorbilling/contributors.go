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
// Order is preserved from the input slice.
func dedupeContributorsByEmail(contributors []Contributor) []Contributor {
	if len(contributors) <= 1 {
		return contributors
	}

	seen := make(map[string]int)
	deduped := make([]Contributor, 0, len(contributors))

	for _, contributor := range contributors {
		if contributor.Email == "" {
			continue
		}

		normalizedEmail := strings.ToLower(strings.TrimSpace(contributor.Email))
		if idx, exists := seen[normalizedEmail]; exists {
			if contributor.LatestCommitDate.After(deduped[idx].LatestCommitDate) {
				deduped[idx] = contributor
			}
		} else {
			seen[normalizedEmail] = len(deduped)
			deduped = append(deduped, contributor)
		}
	}

	if len(deduped) == 0 {
		return nil
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
