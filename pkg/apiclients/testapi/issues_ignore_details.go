package testapi

import (
	"time"
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
	SkipIfFixable() *bool

	// GetPolicyID returns the managed policy ID if this is a managed policy.
	// Returns nil for local policies or if no policy is associated.
	GetPolicyID() *string

	// GetIgnoreReasonType returns the type/category of the ignore reason.
	GetIgnoreReasonType() string

	// GetIgnoredBy returns the user who created the ignore action.
	GetIgnoredBy() *IgnoredBy

	IsActive() bool
}

// issueIgnoreDetailsImpl is the concrete implementation of IssueIgnoreDetails.
type issueIgnoreDetailsImpl struct {
	finding    *FindingData
	policyID   *string
	ignoreData *Ignore
}

// === Suppression Status Methods ===

func (id *issueIgnoreDetailsImpl) GetStatus() SuppressionStatus {
	if !id.isInitialized() {
		return ""
	}
	return id.finding.Attributes.Suppression.Status
}

func (id *issueIgnoreDetailsImpl) GetCreatedAt() *time.Time {
	if !id.isInitialized() {
		return nil
	}
	return id.finding.Attributes.Suppression.CreatedAt
}

func (id *issueIgnoreDetailsImpl) GetExpiresAt() *time.Time {
	if !id.isInitialized() {
		return nil
	}
	return id.finding.Attributes.Suppression.ExpiresAt
}

func (id *issueIgnoreDetailsImpl) GetJustification() *string {
	if !id.isInitialized() {
		return nil
	}
	return id.finding.Attributes.Suppression.Justification
}

func (id *issueIgnoreDetailsImpl) GetPath() *[]string {
	if !id.isInitialized() {
		return nil
	}
	return id.finding.Attributes.Suppression.Path
}

func (id *issueIgnoreDetailsImpl) SkipIfFixable() *bool {
	if !id.isInitialized() {
		return nil
	}
	return id.finding.Attributes.Suppression.SkipIfFixable
}

// === Policy Information Methods ===

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

func (id *issueIgnoreDetailsImpl) GetIgnoreReasonType() string {
	if id.ignoreData == nil || id.ignoreData.Ignore.ReasonType == nil {
		return ""
	}
	return string(*id.ignoreData.Ignore.ReasonType)
}

func (id *issueIgnoreDetailsImpl) GetIgnoredBy() *IgnoredBy {
	if id.ignoreData == nil {
		return nil
	}
	return id.ignoreData.Ignore.IgnoredBy
}

func (id *issueIgnoreDetailsImpl) IsActive() bool {
	if !id.isInitialized() {
		return false
	}

	if id.finding.Attributes.Suppression.Status != SuppressionStatusIgnored {
		return false
	}

	return true
}

func (id *issueIgnoreDetailsImpl) isInitialized() bool {
	if id.finding == nil || id.finding.Attributes == nil || id.finding.Attributes.Suppression == nil {
		return false
	}
	return true
}

// searchFindingForIgnoreAction searches a finding for a matching ignore action.
func searchFindingForIgnoreAction(finding *FindingData, policyIDToMatch *string) *Ignore {
	if finding.Relationships == nil || finding.Relationships.Policy == nil {
		return nil
	}

	policyRel := finding.Relationships.Policy
	if policyRel.Data == nil || policyRel.Data.Attributes == nil {
		return nil
	}

	// Look for Ignore action in the policy attributes
	return findIgnoreActionInPolicies(policyRel.Data.Attributes.Policies, policyIDToMatch)
}

// findIgnoreActionInPolicies searches for an ignore action in a list of policies.
func findIgnoreActionInPolicies(policies []Policy, policyIDToMatch *string) *Ignore {
	for _, policy := range policies {
		if ignoreAction := extractIgnoreActionFromPolicy(policy, policyIDToMatch); ignoreAction != nil {
			return ignoreAction
		}
	}
	return nil
}

// extractIgnoreActionFromPolicy extracts an ignore action from a policy if it matches criteria.
func extractIgnoreActionFromPolicy(policy Policy, policyIDToMatch *string) *Ignore {
	// Check discriminator first to ensure it's an ignore action
	discriminator, err := policy.AppliedPolicy.Discriminator()
	if err != nil || discriminator != "ignore" {
		return nil
	}

	ignoreAction, err := policy.AppliedPolicy.AsIgnore()
	if err != nil {
		return nil
	}

	// For managed policies, verify the PolicyRef in the Ignore action matches
	if policyIDToMatch != nil && policy.Id.String() == *policyIDToMatch {
		return &ignoreAction
	}

	return nil
}
