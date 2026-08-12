package contributorbilling

import (
	"strings"
	"time"

	"github.com/rs/zerolog"

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
// Skips contributors with empty emails. Order is preserved from the input slice.
func dedupeContributorsByEmail(contributors []Contributor) []Contributor {
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

func fillContributors(item *BillingItem, defaultRepoPath string, now time.Time, logger *zerolog.Logger) error {
	if len(item.Contributors) > 0 {
		return nil
	}

	repoPath := item.RepoPath
	if repoPath == "" {
		repoPath = defaultRepoPath
	}

	contributors, err := collectContributors(repoPath, now)
	if err != nil {
		logger.Debug().Err(err).Str("repo_path", repoPath).Msg("contributor billing: git collection failed, continuing with empty contributors")
		return err
	}

	item.Contributors = contributors
	return nil
}

func dedupeContributor(item *BillingItem) {
	if len(item.Contributors) == 0 {
		return
	}
	item.Contributors = dedupeContributorsByEmail(item.Contributors)
}
