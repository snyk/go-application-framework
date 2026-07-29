package contributorbilling

import (
	"encoding/json"

	"github.com/rs/zerolog"
	v20260729 "github.com/snyk/go-application-framework/pkg/apiclients/entitlements_service/2026-07-29"
)

func buildIngestRequest(capability, scopeID string, items []BillingItem, logger *zerolog.Logger) v20260729.ContributorIngestRequest {
	payloadItems := make([]v20260729.ContributorIngestItem, len(items))
	for i, item := range items {
		contributors := make([]v20260729.ContributorIngestContributor, 0, len(item.Contributors))
		for _, contributor := range item.Contributors {
			if contributor.LatestCommitDate.IsZero() {
				if logger != nil {
					logger.Debug().
						Str("email", contributor.Email).
						Msg("contributor billing: skipping contributor with zero latest commit date")
				}
				continue
			}

			contributors = append(contributors, v20260729.ContributorIngestContributor{
				Email:            contributor.Email,
				LatestCommitDate: contributor.LatestCommitDate.UTC(),
			})
		}

		payloadItems[i] = v20260729.ContributorIngestItem{
			ScopeId:      scopeID,
			TargetId:     item.TargetID,
			Contributors: contributors,
		}
	}

	return v20260729.ContributorIngestRequest{
		Source:     SourceCLI,
		Capability: capability,
		Items:      payloadItems,
	}
}

func marshalIngestRequest(capability, scopeID string, items []BillingItem, logger *zerolog.Logger) ([]byte, error) {
	request := buildIngestRequest(capability, scopeID, items, logger)
	return json.Marshal(request)
}
