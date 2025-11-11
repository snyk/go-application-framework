package testapi

import (
	"time"

	"github.com/google/uuid"
)

// IssueIgnoreDetails provides combined information about issue suppression/ignore status,
// including both suppression data and linked policy information.
// This interface uses accessor methods to hide implementation details.
type IssueIgnoreDetails interface {
	// === Suppression Status ===

	// GetStatus returns the suppression status (ignored, pending_ignore_approval, etc.).
	GetStatus() SuppressionStatus

	// GetCreatedAt returns when the suppression was first created.
	GetCreatedAt() *time.Time

	// GetExpiresAt returns when the suppression will expire.
	GetExpiresAt() *time.Time

	// GetJustification returns the reason given for the suppression.
	GetJustification() *string

	// GetPath returns the dependency path to the vulnerable package.
	GetPath() *[]string

	// GetSkipIfFixable returns whether to skip the suppression if a fix is available.
	GetSkipIfFixable() *bool

	// === Policy Information ===

	// IsLocalPolicy returns true if this is a local policy, false if managed.
	// Returns nil if policy type cannot be determined.
	IsLocalPolicy() *bool

	// GetPolicyID returns the managed policy ID if this is a managed policy.
	// Returns nil for local policies or if no policy is associated.
	GetPolicyID() *string

	// === Ignore Action Details ===
	// These methods return data from the expanded policy ignore action if available.

	// GetIgnoreReason returns the reason for ignoring from the policy action.
	GetIgnoreReason() string

	// GetIgnoreSource returns the source of the ignore action (cli, web, etc.).
	GetIgnoreSource() string

	// GetIgnoreReasonType returns the type/category of the ignore reason.
	GetIgnoreReasonType() *IgnoreDetailsReasonType

	// GetIgnoreCreated returns when the ignore was created from the policy action.
	GetIgnoreCreated() *time.Time

	// GetIgnoreExpires returns when the ignore expires from the policy action.
	GetIgnoreExpires() *time.Time

	// GetDisregardIfFixable returns whether to disregard if fixable from the policy action.
	GetDisregardIfFixable() *bool
}

// issueIgnoreDetailsImpl is the concrete implementation of IssueIgnoreDetails.
type issueIgnoreDetailsImpl struct {
	suppression   *Suppression
	isLocalPolicy *bool
	policyID      *string
	ignoreData    *Ignore
}

// === Suppression Status Methods ===

func (id *issueIgnoreDetailsImpl) GetStatus() SuppressionStatus {
	if id.suppression == nil {
		return ""
	}
	return id.suppression.Status
}

func (id *issueIgnoreDetailsImpl) GetCreatedAt() *time.Time {
	if id.suppression == nil {
		return nil
	}
	return id.suppression.CreatedAt
}

func (id *issueIgnoreDetailsImpl) GetExpiresAt() *time.Time {
	if id.suppression == nil {
		return nil
	}
	return id.suppression.ExpiresAt
}

func (id *issueIgnoreDetailsImpl) GetJustification() *string {
	if id.suppression == nil {
		return nil
	}
	return id.suppression.Justification
}

func (id *issueIgnoreDetailsImpl) GetPath() *[]string {
	if id.suppression == nil {
		return nil
	}
	return id.suppression.Path
}

func (id *issueIgnoreDetailsImpl) GetSkipIfFixable() *bool {
	if id.suppression == nil {
		return nil
	}
	return id.suppression.SkipIfFixable
}

// === Policy Information Methods ===

func (id *issueIgnoreDetailsImpl) IsLocalPolicy() *bool {
	return id.isLocalPolicy
}

func (id *issueIgnoreDetailsImpl) GetPolicyID() *string {
	return id.policyID
}

// === Ignore Action Details Methods ===

func (id *issueIgnoreDetailsImpl) GetIgnoreReason() string {
	if id.ignoreData == nil {
		return ""
	}
	return id.ignoreData.Ignore.Reason
}

func (id *issueIgnoreDetailsImpl) GetIgnoreSource() string {
	if id.ignoreData == nil {
		return ""
	}
	return id.ignoreData.Ignore.Source
}

func (id *issueIgnoreDetailsImpl) GetIgnoreReasonType() *IgnoreDetailsReasonType {
	if id.ignoreData == nil {
		return nil
	}
	return id.ignoreData.Ignore.ReasonType
}

func (id *issueIgnoreDetailsImpl) GetIgnoreCreated() *time.Time {
	if id.ignoreData == nil {
		return nil
	}
	return id.ignoreData.Ignore.Created
}

func (id *issueIgnoreDetailsImpl) GetIgnoreExpires() *time.Time {
	if id.ignoreData == nil {
		return nil
	}
	return id.ignoreData.Ignore.Expires
}

func (id *issueIgnoreDetailsImpl) GetDisregardIfFixable() *bool {
	if id.ignoreData == nil {
		return nil
	}
	return id.ignoreData.Ignore.DisregardIfFixable
}

// newIgnoreDetailsFromSuppression creates an IssueIgnoreDetails from suppression data and findings.
func newIgnoreDetailsFromSuppression(suppression *Suppression, findings []*FindingData) IssueIgnoreDetails {
	if suppression == nil {
		return nil
	}

	result := &issueIgnoreDetailsImpl{
		suppression: suppression,
	}

	// Extract policy information from suppression
	if suppression.Policy != nil {
		// Determine policy type and ID by checking the structure
		// PolicyRef is a union of either a string (local) or an object with ID (managed)

		// First, try as a string (local policy)
		if localRef, err := suppression.Policy.AsPolicyRef0(); err == nil && localRef == PolicyRef0LocalPolicy {
			// It's a local policy
			isLocal := true
			result.isLocalPolicy = &isLocal
		} else {
			// Try as a managed policy (has ID field)
			if managedRef, err := suppression.Policy.AsManagedPolicyRef(); err == nil && managedRef.Id != uuid.Nil {
				// It's a managed policy with a valid ID
				isLocal := false
				result.isLocalPolicy = &isLocal
				idStr := managedRef.Id.String()
				result.policyID = &idStr
			}
			// If both fail, policy type cannot be determined (isLocalPolicy remains nil)
		}

		// Try to find the matching expanded policy data in findings
		result.ignoreData = findMatchingIgnoreData(suppression.Policy, findings)
	}

	return result
}

// findMatchingIgnoreData finds the Ignore action that matches the given policy reference.
func findMatchingIgnoreData(policyRef *PolicyRef, findings []*FindingData) *Ignore {
	if policyRef == nil {
		return nil
	}

	policyIDToMatch, isLocalPolicy := extractPolicyTypeFromRef(policyRef)

	// Search through findings for matching policy
	for _, finding := range findings {
		if ignoreAction := searchFindingForIgnoreAction(finding, policyIDToMatch, isLocalPolicy); ignoreAction != nil {
			return ignoreAction
		}
	}

	return nil
}

// extractPolicyTypeFromRef determines if a PolicyRef is local or managed and returns the policy ID.
func extractPolicyTypeFromRef(policyRef *PolicyRef) (*string, bool) {
	// First, try as a string (local policy)
	if localRef, err := policyRef.AsPolicyRef0(); err == nil && localRef == PolicyRef0LocalPolicy {
		return nil, true
	}

	// Try as a managed policy (has ID field)
	if managedRef, err := policyRef.AsManagedPolicyRef(); err == nil && managedRef.Id != uuid.Nil {
		idStr := managedRef.Id.String()
		return &idStr, false
	}

	return nil, false
}

// searchFindingForIgnoreAction searches a finding for a matching ignore action.
func searchFindingForIgnoreAction(finding *FindingData, policyIDToMatch *string, isLocalPolicy bool) *Ignore {
	if finding.Relationships == nil || finding.Relationships.Policy == nil {
		return nil
	}

	policyRel := finding.Relationships.Policy
	if policyRel.Data == nil || policyRel.Data.Attributes == nil {
		return nil
	}

	// For managed policies, match the policy relationship ID
	if policyIDToMatch != nil && policyRel.Data.Id.String() != *policyIDToMatch {
		return nil // This relationship is for a different policy
	}

	// Look for Ignore action in the policy attributes
	return findIgnoreActionInPolicies(policyRel.Data.Attributes.Policies, policyIDToMatch, isLocalPolicy)
}

// findIgnoreActionInPolicies searches for an ignore action in a list of policies.
func findIgnoreActionInPolicies(policies []Policy, policyIDToMatch *string, isLocalPolicy bool) *Ignore {
	for _, policy := range policies {
		if ignoreAction := extractIgnoreActionFromPolicy(policy, policyIDToMatch, isLocalPolicy); ignoreAction != nil {
			return ignoreAction
		}
	}
	return nil
}

// extractIgnoreActionFromPolicy extracts an ignore action from a policy if it matches criteria.
func extractIgnoreActionFromPolicy(policy Policy, policyIDToMatch *string, isLocalPolicy bool) *Ignore {
	// Check discriminator first to ensure it's an ignore action
	discriminator, err := policy.AppliedPolicy.Discriminator()
	if err != nil || discriminator != "ignore" {
		return nil
	}

	ignoreAction, err := policy.AppliedPolicy.AsIgnore()
	if err != nil {
		return nil
	}

	// For local policies, we found an ignore action in a local policy context
	if isLocalPolicy {
		return &ignoreAction
	}

	// For managed policies, verify the PolicyRef in the Ignore action matches
	if policyIDToMatch != nil && ignoreAction.PolicyRef != nil {
		if ignoreAction.PolicyRef.Id.String() == *policyIDToMatch {
			return &ignoreAction
		}
	}

	return nil
}
