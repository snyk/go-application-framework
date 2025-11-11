package testapi_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

func TestIssue_GetIgnoreDetails_NoSuppression(t *testing.T) {
	findings := []*testapi.FindingData{
		{
			Attributes: &testapi.FindingAttributes{
				FindingType: testapi.FindingTypeSca,
				Key:         "test-key",
				Title:       "Test Issue",
				Suppression: nil,
			},
			Id: func() *openapi_types.UUID { id := uuid.New(); return &id }(),
		},
	}

	issue, err := testapi.NewIssueFromFindings(findings)
	require.NoError(t, err)

	ignoreDetails := issue.GetIgnoreDetails()
	assert.Nil(t, ignoreDetails)
}

func TestIssue_GetIgnoreDetails_SuppressionWithoutPolicy(t *testing.T) {
	createdAt := time.Now()
	status := testapi.SuppressionStatusIgnored

	findings := []*testapi.FindingData{
		{
			Attributes: &testapi.FindingAttributes{
				FindingType: testapi.FindingTypeSca,
				Key:         "test-key",
				Title:       "Test Issue",
				Suppression: &testapi.Suppression{
					Status:    status,
					CreatedAt: &createdAt,
					Policy:    nil,
				},
			},
			Id: func() *openapi_types.UUID { id := uuid.New(); return &id }(),
		},
	}

	issue, err := testapi.NewIssueFromFindings(findings)
	require.NoError(t, err)

	ignoreDetails := issue.GetIgnoreDetails()
	require.NotNil(t, ignoreDetails)

	assert.Equal(t, status, ignoreDetails.GetStatus())
	assert.NotNil(t, ignoreDetails.GetCreatedAt())

	assert.Nil(t, ignoreDetails.IsLocalPolicy())
	assert.Empty(t, ignoreDetails.GetIgnoreReason())
}

func TestIssue_GetIgnoreDetails_LocalPolicy(t *testing.T) {
	status := testapi.SuppressionStatusIgnored

	var localPolicyRef testapi.PolicyRef
	err := localPolicyRef.FromPolicyRef0(testapi.PolicyRef0LocalPolicy)
	require.NoError(t, err)

	findings := []*testapi.FindingData{
		{
			Attributes: &testapi.FindingAttributes{
				FindingType: testapi.FindingTypeSca,
				Key:         "test-key",
				Title:       "Test Issue",
				Suppression: &testapi.Suppression{
					Status: status,
					Policy: &localPolicyRef,
				},
			},
			Id: func() *openapi_types.UUID { id := uuid.New(); return &id }(),
		},
	}

	issue, err := testapi.NewIssueFromFindings(findings)
	require.NoError(t, err)

	ignoreDetails := issue.GetIgnoreDetails()
	require.NotNil(t, ignoreDetails)

	isLocalPolicy := ignoreDetails.IsLocalPolicy()
	require.NotNil(t, isLocalPolicy)
	assert.True(t, *isLocalPolicy)
	assert.Nil(t, ignoreDetails.GetPolicyID())
}

func TestIssue_GetIgnoreDetails_ManagedPolicy(t *testing.T) {
	status := testapi.SuppressionStatusIgnored
	policyID := uuid.New()

	var managedPolicyRef testapi.PolicyRef
	err := managedPolicyRef.FromManagedPolicyRef(testapi.ManagedPolicyRef{
		Id: policyID,
	})
	require.NoError(t, err)

	findings := []*testapi.FindingData{
		{
			Attributes: &testapi.FindingAttributes{
				FindingType: testapi.FindingTypeSca,
				Key:         "test-key",
				Title:       "Test Issue",
				Suppression: &testapi.Suppression{
					Status: status,
					Policy: &managedPolicyRef,
				},
			},
			Id: func() *openapi_types.UUID { id := uuid.New(); return &id }(),
		},
	}

	issue, err := testapi.NewIssueFromFindings(findings)
	require.NoError(t, err)

	ignoreDetails := issue.GetIgnoreDetails()
	require.NotNil(t, ignoreDetails)

	isLocalPolicy := ignoreDetails.IsLocalPolicy()
	require.NotNil(t, isLocalPolicy)
	assert.False(t, *isLocalPolicy)

	managedPolicyID := ignoreDetails.GetPolicyID()
	require.NotNil(t, managedPolicyID)
	assert.Equal(t, policyID.String(), *managedPolicyID)
}
