package contributorbilling

import (
	"encoding/json"
	"time"

	"github.com/rs/zerolog"
)

type ingestPayload struct {
	Source     string       `json:"source"`
	Capability string       `json:"capability"`
	Items      []ingestItem `json:"items"`
}

type ingestItem struct {
	ScopeID      string              `json:"scope_id"`
	TargetID     string              `json:"target_id"`
	Contributors []ingestContributor `json:"contributors"`
}

type ingestContributor struct {
	Email            string `json:"email"`
	LatestCommitDate string `json:"latest_commit_date"`
}

func buildIngestPayload(capability, scopeID string, items []BillingItem, logger *zerolog.Logger) ingestPayload {
	payloadItems := make([]ingestItem, len(items))
	for i, item := range items {
		contributors := make([]ingestContributor, 0, len(item.Contributors))
		for _, contributor := range item.Contributors {
			if contributor.LatestCommitDate.IsZero() {
				if logger != nil {
					logger.Debug().
						Str("email", contributor.Email).
						Msg("contributor billing: skipping contributor with zero latest commit date")
				}
				continue
			}

			contributors = append(contributors, ingestContributor{
				Email:            contributor.Email,
				LatestCommitDate: contributor.LatestCommitDate.UTC().Format(time.RFC3339),
			})
		}

		payloadItems[i] = ingestItem{
			ScopeID:      scopeID,
			TargetID:     item.TargetID,
			Contributors: contributors,
		}
	}

	return ingestPayload{
		Source:     SourceCLI,
		Capability: capability,
		Items:      payloadItems,
	}
}

func marshalIngestPayload(capability, scopeID string, items []BillingItem, logger *zerolog.Logger) ([]byte, error) {
	payload := buildIngestPayload(capability, scopeID, items, logger)
	return json.Marshal(payload)
}
