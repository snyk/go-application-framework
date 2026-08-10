package contributorbilling

import (
	"sort"
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
// keeping the latest commit date per exact email match (case-sensitive, as git returns).
func dedupeContributorsByEmail(contributors []Contributor) []Contributor {
	if len(contributors) <= 1 {
		return contributors
	}

	byEmail := make(map[string]Contributor, len(contributors))
	order := make([]string, 0, len(contributors))

	for _, contributor := range contributors {
		if contributor.Email == "" {
			continue
		}

		existing, seen := byEmail[contributor.Email]
		if !seen {
			order = append(order, contributor.Email)
			byEmail[contributor.Email] = contributor
			continue
		}

		if contributor.LatestCommitDate.After(existing.LatestCommitDate) {
			byEmail[contributor.Email] = contributor
		}
	}

	if len(order) == 0 {
		return nil
	}

	sort.Strings(order)

	deduped := make([]Contributor, 0, len(order))
	for _, email := range order {
		deduped = append(deduped, byEmail[email])
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
