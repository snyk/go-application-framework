package contributorbilling

import (
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
