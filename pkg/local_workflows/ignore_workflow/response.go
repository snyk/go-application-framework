package ignore_workflow

import (
	"time"

	"github.com/snyk/code-client-go/sarif"

	v20241015 "github.com/snyk/go-application-framework/internal/api/policy/2024-10-15"
)

func policyReviewToSarifStatus(review v20241015.PolicyReview) sarif.SuppresionStatus {
	switch review {
	case v20241015.PolicyReviewPending:
		return sarif.UnderReview
	case v20241015.PolicyReviewRejected:
		return sarif.Rejected
	case v20241015.PolicyReviewApproved:
		return sarif.Accepted
	case v20241015.PolicyReviewNotRequired:
		return sarif.Accepted
	default:
		return ""
	}
}

// currently this is only used in the IDE. IDE needs a response to update its cache after creating an ignore.
func policyResponseToSarifSuppression(policyResponse *v20241015.PolicyResponse) *sarif.Suppression {
	if policyResponse == nil {
		return nil
	}
	var expires *string
	if policyResponse.Attributes.Action.Data.Expires != nil {
		expiresStr := policyResponse.Attributes.Action.Data.Expires.Format(time.RFC3339)
		expires = &expiresStr
	}

	justification := ""
	if policyResponse.Attributes.Action.Data.Reason != nil {
		justification = *policyResponse.Attributes.Action.Data.Reason
	}

	return &sarif.Suppression{
		Guid:          policyResponse.Id.String(),
		Justification: justification,
		Status:        policyReviewToSarifStatus(policyResponse.Attributes.Review),
		Properties: sarif.SuppressionProperties{
			Expiration: expires,
			IgnoredOn:  policyResponse.Attributes.CreatedAt.Format(time.RFC3339),
			Category:   sarif.Category(policyResponse.Attributes.Action.Data.IgnoreType),
			IgnoredBy: sarif.IgnoredBy{
				Name:  policyResponse.Attributes.CreatedBy.Name,
				Email: policyResponse.Attributes.CreatedBy.Email,
			},
		},
	}
}
