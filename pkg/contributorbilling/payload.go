package contributorbilling

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	v20260729 "github.com/snyk/go-application-framework/pkg/apiclients/entitlements_service/2026-07-29"
)

func buildIngestRequest(item BillingItem, logger *zerolog.Logger) v20260729.CreateContributingDevsApplicationVndAPIPlusJSONRequestBody {
	contributors := make([]v20260729.Contributor, 0, len(item.Contributors))
	for _, contributor := range item.Contributors {
		if contributor.LatestCommitDate.IsZero() {
			if logger != nil {
				logger.Debug().
					Str("email", contributor.Email).
					Msg("contributor billing: skipping contributor with zero latest commit date")
			}
			continue
		}

		contributors = append(contributors, v20260729.Contributor{
			Email:      contributor.Email,
			CommitDate: contributor.LatestCommitDate.UTC(),
		})
	}

	request := v20260729.CreateContributingDevsApplicationVndAPIPlusJSONRequestBody{}
	request.Data.Type = v20260729.ContributingDevs
	request.Data.Attributes = v20260729.ContributingDevsIngestAttributes{
		ContributorsEntityId: contributorsEntityID(item),
		Contributors:         contributors,
	}
	return request
}

func contributorsEntityID(item BillingItem) string {
	entityType := strings.TrimSpace(item.EntityType)
	if entityType == "" {
		entityType = EntityTypeProject
	}

	return fmt.Sprintf("%s:%s", entityType, item.EntityID)
}
