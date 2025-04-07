package ignore_workflow

import (
	"github.com/snyk/code-client-go/sarif"

	v20241015 "github.com/snyk/go-application-framework/internal/api/policy/2024-10-15"
)

type IgnoreResponseType struct {
	IgnoreId string                 `json:"id"`
	Status   sarif.SuppresionStatus `json:"reason"`
}

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

func policyResponseToIgnoreResponse(policyResponse *v20241015.PolicyResponse) *IgnoreResponseType {
	if policyResponse == nil {
		return nil
	}
	return &IgnoreResponseType{
		IgnoreId: policyResponse.Id.String(),
		Status:   policyReviewToSarifStatus(policyResponse.Attributes.Review),
	}
}
