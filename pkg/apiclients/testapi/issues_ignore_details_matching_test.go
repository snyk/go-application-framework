package testapi_test

import (
	"testing"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

// Helper to create finding with policy relationship
func createFindingWithPolicy(policyID uuid.UUID, appliedPolicy testapi.AppliedPolicy, suppressionPolicy *testapi.PolicyRef) *testapi.FindingData {
	policy := testapi.Policy{
		Id:            policyID,
		Type:          testapi.LegacyPolicySnapshot,
		AppliedPolicy: appliedPolicy,
	}

	policyAttrs := testapi.PolicyAttributes{
		Policies: []testapi.Policy{policy},
	}

	findingID := uuid.New()
	return &testapi.FindingData{
		Attributes: &testapi.FindingAttributes{
			FindingType: testapi.FindingTypeSca,
			Key:         "test-key",
			Title:       "Test Issue",
			Suppression: &testapi.Suppression{
				Status: testapi.SuppressionStatusIgnored,
				Policy: suppressionPolicy,
			},
		},
		Id: &findingID,
		Relationships: &struct {
			Asset *struct {
				Data *struct {
					Id   openapi_types.UUID `json:"id"`
					Type string             `json:"type"`
				} `json:"data,omitempty"`
				Links testapi.IoSnykApiCommonRelatedLink `json:"links"`
				Meta  *testapi.IoSnykApiCommonMeta       `json:"meta,omitempty"`
			} `json:"asset,omitempty"`
			Fix *struct {
				Data *struct {
					Attributes *testapi.FixAttributes `json:"attributes,omitempty"`
					Id         openapi_types.UUID     `json:"id"`
					Type       string                 `json:"type"`
				} `json:"data,omitempty"`
			} `json:"fix,omitempty"`
			Org *struct {
				Data *struct {
					Id   openapi_types.UUID `json:"id"`
					Type string             `json:"type"`
				} `json:"data,omitempty"`
			} `json:"org,omitempty"`
			Policy *struct {
				Data *struct {
					Attributes *testapi.PolicyAttributes `json:"attributes,omitempty"`
					Id         openapi_types.UUID        `json:"id"`
					Type       string                    `json:"type"`
				} `json:"data,omitempty"`
				Links testapi.IoSnykApiCommonRelatedLink `json:"links"`
				Meta  *testapi.IoSnykApiCommonMeta       `json:"meta,omitempty"`
			} `json:"policy,omitempty"`
			Test *struct {
				Data *struct {
					Id   openapi_types.UUID `json:"id"`
					Type string             `json:"type"`
				} `json:"data,omitempty"`
				Links testapi.IoSnykApiCommonRelatedLink `json:"links"`
				Meta  *testapi.IoSnykApiCommonMeta       `json:"meta,omitempty"`
			} `json:"test,omitempty"`
		}{
			Policy: &struct {
				Data *struct {
					Attributes *testapi.PolicyAttributes `json:"attributes,omitempty"`
					Id         openapi_types.UUID        `json:"id"`
					Type       string                    `json:"type"`
				} `json:"data,omitempty"`
				Links testapi.IoSnykApiCommonRelatedLink `json:"links"`
				Meta  *testapi.IoSnykApiCommonMeta       `json:"meta,omitempty"`
			}{
				Data: &struct {
					Attributes *testapi.PolicyAttributes `json:"attributes,omitempty"`
					Id         openapi_types.UUID        `json:"id"`
					Type       string                    `json:"type"`
				}{
					Attributes: &policyAttrs,
					Id:         policyID,
					Type:       "policies",
				},
			},
		},
	}
}

func TestIssue_GetIgnoreDetails_MatchingLocalPolicy(t *testing.T) {
	var localPolicyRef testapi.PolicyRef
	err := localPolicyRef.FromPolicyRef0(testapi.PolicyRef0LocalPolicy)
	require.NoError(t, err)

	ignore := testapi.Ignore{
		ActionType: testapi.IgnoreActionTypeIgnore,
		Ignore: testapi.IgnoreDetails{
			Reason: "Not vulnerable",
			Source: "cli",
		},
	}

	var appliedPolicy testapi.AppliedPolicy
	err = appliedPolicy.FromIgnore(ignore)
	require.NoError(t, err)

	policyID := uuid.New()
	finding := createFindingWithPolicy(policyID, appliedPolicy, &localPolicyRef)

	issue, err := testapi.NewIssueFromFindings([]*testapi.FindingData{finding})
	require.NoError(t, err)

	ignoreDetails := issue.GetIgnoreDetails()
	require.NotNil(t, ignoreDetails)

	// Should find ignore data for local policy
	ignoreReason := ignoreDetails.GetIgnoreReason()
	assert.Equal(t, "Not vulnerable", ignoreReason)
}

func TestIssue_GetIgnoreDetails_MatchingManagedPolicy(t *testing.T) {
	managedPolicyID := uuid.New()

	var managedPolicyRef testapi.PolicyRef
	err := managedPolicyRef.FromManagedPolicyRef(testapi.ManagedPolicyRef{
		Id: managedPolicyID,
	})
	require.NoError(t, err)

	snykPolicyRef := testapi.SnykPolicyRef{
		Id:    managedPolicyID,
		Owner: testapi.Org,
	}

	ignore := testapi.Ignore{
		ActionType: testapi.IgnoreActionTypeIgnore,
		Ignore: testapi.IgnoreDetails{
			Reason: "Accepted risk",
			Source: "web",
		},
		PolicyRef: &snykPolicyRef,
	}

	var appliedPolicy testapi.AppliedPolicy
	err = appliedPolicy.FromIgnore(ignore)
	require.NoError(t, err)

	finding := createFindingWithPolicy(managedPolicyID, appliedPolicy, &managedPolicyRef)

	issue, err := testapi.NewIssueFromFindings([]*testapi.FindingData{finding})
	require.NoError(t, err)

	ignoreDetails := issue.GetIgnoreDetails()
	require.NotNil(t, ignoreDetails)

	// Verify policy info
	assert.Equal(t, "Accepted risk", ignoreDetails.GetIgnoreReason())
	assert.Equal(t, "web", ignoreDetails.GetIgnoreSource())

	// Verify policy ID
	policyID := ignoreDetails.GetPolicyID()
	require.NotNil(t, policyID)
	assert.Equal(t, managedPolicyID.String(), *policyID)
}

func TestIssue_GetIgnoreDetails_WrongPolicyID(t *testing.T) {
	correctPolicyID := uuid.New()
	wrongPolicyID := uuid.New()

	var managedPolicyRef testapi.PolicyRef
	err := managedPolicyRef.FromManagedPolicyRef(testapi.ManagedPolicyRef{
		Id: correctPolicyID,
	})
	require.NoError(t, err)

	wrongSnykPolicyRef := testapi.SnykPolicyRef{
		Id:    wrongPolicyID,
		Owner: testapi.Org,
	}

	ignore := testapi.Ignore{
		ActionType: testapi.IgnoreActionTypeIgnore,
		Ignore: testapi.IgnoreDetails{
			Reason: "Should not match",
			Source: "web",
		},
		PolicyRef: &wrongSnykPolicyRef,
	}

	var appliedPolicy testapi.AppliedPolicy
	err = appliedPolicy.FromIgnore(ignore)
	require.NoError(t, err)

	// Finding has wrong policy ID in relationships
	finding := createFindingWithPolicy(wrongPolicyID, appliedPolicy, &managedPolicyRef)

	issue, err := testapi.NewIssueFromFindings([]*testapi.FindingData{finding})
	require.NoError(t, err)

	ignoreDetails := issue.GetIgnoreDetails()
	require.NotNil(t, ignoreDetails)

	// Should NOT find ignore data because IDs don't match
	ignoreReason := ignoreDetails.GetIgnoreReason()
	assert.Empty(t, ignoreReason, "Should not match when policy IDs differ")
}

func TestIssue_GetIgnoreDetails_NonIgnoreAction(t *testing.T) {
	policyID := uuid.New()

	var managedPolicyRef testapi.PolicyRef
	err := managedPolicyRef.FromManagedPolicyRef(testapi.ManagedPolicyRef{
		Id: policyID,
	})
	require.NoError(t, err)

	// Create severity change action instead of ignore
	severityChange := testapi.SeverityChange{
		ActionType: testapi.SeverityChangeActionTypeSeverityChange,
		PolicyRef: testapi.SnykPolicyRef{
			Id:    policyID,
			Owner: testapi.Org,
		},
	}

	var appliedPolicy testapi.AppliedPolicy
	err = appliedPolicy.FromSeverityChange(severityChange)
	require.NoError(t, err)

	finding := createFindingWithPolicy(policyID, appliedPolicy, &managedPolicyRef)

	issue, err := testapi.NewIssueFromFindings([]*testapi.FindingData{finding})
	require.NoError(t, err)

	ignoreDetails := issue.GetIgnoreDetails()
	require.NotNil(t, ignoreDetails)

	// Policy info should be present
	isLocalPolicy := ignoreDetails.IsLocalPolicy()
	require.NotNil(t, isLocalPolicy)
	assert.False(t, *isLocalPolicy)

	// But no ignore data since it's not an ignore action
	ignoreReason := ignoreDetails.GetIgnoreReason()
	assert.Empty(t, ignoreReason, "Should not find ignore data for non-ignore actions")
}

func TestIssue_GetIgnoreDetails_MultipleFindings(t *testing.T) {
	managedPolicyID := uuid.New()

	var managedPolicyRef testapi.PolicyRef
	err := managedPolicyRef.FromManagedPolicyRef(testapi.ManagedPolicyRef{
		Id: managedPolicyID,
	})
	require.NoError(t, err)

	snykPolicyRef := testapi.SnykPolicyRef{
		Id:    managedPolicyID,
		Owner: testapi.Org,
	}

	ignore := testapi.Ignore{
		ActionType: testapi.IgnoreActionTypeIgnore,
		Ignore: testapi.IgnoreDetails{
			Reason: "Accepted risk",
			Source: "web",
		},
		PolicyRef: &snykPolicyRef,
	}

	var appliedPolicy testapi.AppliedPolicy
	err = appliedPolicy.FromIgnore(ignore)
	require.NoError(t, err)

	// Create multiple findings, only one with policy relationship
	finding1 := createFindingWithPolicy(managedPolicyID, appliedPolicy, &managedPolicyRef)

	findingID2 := uuid.New()
	finding2 := &testapi.FindingData{
		Attributes: &testapi.FindingAttributes{
			FindingType: testapi.FindingTypeSca,
			Key:         "test-key",
			Title:       "Test Issue",
			Suppression: &testapi.Suppression{
				Status: testapi.SuppressionStatusIgnored,
				Policy: &managedPolicyRef,
			},
		},
		Id: &findingID2,
		// No relationships
	}

	issue, err := testapi.NewIssueFromFindings([]*testapi.FindingData{finding1, finding2})
	require.NoError(t, err)

	ignoreDetails := issue.GetIgnoreDetails()
	require.NotNil(t, ignoreDetails)

	// Should find ignore data from the finding that has relationships
	ignoreReason := ignoreDetails.GetIgnoreReason()
	assert.Equal(t, "Accepted risk", ignoreReason)
}
