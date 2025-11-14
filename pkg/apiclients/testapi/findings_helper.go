package testapi

import "github.com/google/uuid"

func (f *FindingData) GetIgnoreDetails() IssueIgnoreDetails {
	if f.Attributes == nil || f.Attributes.Suppression == nil {
		return nil
	}
	result := &issueIgnoreDetailsImpl{
		finding: f,
	}

	// Extract policy information from suppression
	if result.finding.Attributes.Suppression.Policy != nil {
		if localRef, err := result.finding.Attributes.Suppression.Policy.AsPolicyRef0(); !(err == nil && localRef == PolicyRef0LocalPolicy) {
			// Try as a managed policy (has ID field)
			if managedRef, err := result.finding.Attributes.Suppression.Policy.AsManagedPolicyRef(); err == nil && managedRef.Id != uuid.Nil {
				// It's a managed policy with a valid ID
				idStr := managedRef.Id.String()
				result.policyID = &idStr
				result.ignoreData = searchFindingForIgnoreAction(result.finding, result.policyID)
			}
			// If both fail, policy type cannot be determined (isLocalPolicy remains nil)
		}
	}

	return result
}
