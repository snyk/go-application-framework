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

	assert.Empty(t, ignoreDetails.GetJustification())
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

	managedPolicyID := ignoreDetails.GetPolicyID()
	require.NotNil(t, managedPolicyID)
	assert.Equal(t, policyID.String(), *managedPolicyID)
}

func TestIssueIgnoreDetails_SuppressionFields(t *testing.T) {
	createdAt := time.Now().Add(-24 * time.Hour)
	expiresAt := time.Now().Add(24 * time.Hour)
	justification := "Not applicable in test environment"
	path := []string{"path", "to", "dependency"}
	skipIfFixable := true

	findings := []*testapi.FindingData{
		{
			Attributes: &testapi.FindingAttributes{
				FindingType: testapi.FindingTypeSca,
				Key:         "test-key",
				Title:       "Test Issue",
				Suppression: &testapi.Suppression{
					Status:        testapi.SuppressionStatusIgnored,
					CreatedAt:     &createdAt,
					ExpiresAt:     &expiresAt,
					Justification: &justification,
					Path:          &path,
					SkipIfFixable: &skipIfFixable,
				},
			},
			Id: func() *openapi_types.UUID { id := uuid.New(); return &id }(),
		},
	}

	issue, err := testapi.NewIssueFromFindings(findings)
	require.NoError(t, err)

	details := issue.GetIgnoreDetails()
	require.NotNil(t, details)

	assert.Equal(t, testapi.SuppressionStatusIgnored, details.GetStatus())
	assert.Equal(t, createdAt, *details.GetCreatedAt())
	assert.Equal(t, expiresAt, *details.GetExpiresAt())
	assert.Equal(t, justification, *details.GetJustification())
	assert.Equal(t, path, *details.GetPath())
	assert.Equal(t, skipIfFixable, *details.SkipIfFixable())
}

func TestIssueIgnoreDetails_IsActive(t *testing.T) {
	tests := []struct {
		name            string
		status          testapi.SuppressionStatus
		expectNilDetail bool
		expectActive    bool
	}{
		{"ignored status", testapi.SuppressionStatusIgnored, false, true},
		{"pending status", testapi.SuppressionStatusPendingIgnoreApproval, true, false},
		{"empty status", "", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := []*testapi.FindingData{
				{
					Attributes: &testapi.FindingAttributes{
						FindingType: testapi.FindingTypeSca,
						Key:         "test-key",
						Suppression: &testapi.Suppression{
							Status: tt.status,
						},
					},
					Id: func() *openapi_types.UUID { id := uuid.New(); return &id }(),
				},
			}

			issue, err := testapi.NewIssueFromFindings(findings)
			require.NoError(t, err)

			details := issue.GetIgnoreDetails()
			if tt.expectNilDetail {
				assert.Nil(t, details)
			} else {
				require.NotNil(t, details)
				assert.Equal(t, tt.expectActive, details.IsActive())
			}
		})
	}
}

func TestIssueIgnoreDetails_EmptySuppressionReturnsNil(t *testing.T) {
	findings := []*testapi.FindingData{
		{
			Attributes: &testapi.FindingAttributes{
				FindingType: testapi.FindingTypeSca,
				Key:         "test-key",
				Suppression: &testapi.Suppression{},
			},
			Id: func() *openapi_types.UUID { id := uuid.New(); return &id }(),
		},
	}

	issue, err := testapi.NewIssueFromFindings(findings)
	require.NoError(t, err)

	details := issue.GetIgnoreDetails()
	assert.Nil(t, details)
}

func TestIssueIgnoreDetails_IgnoreData(t *testing.T) {
	policyID := uuid.New()
	reasonType := testapi.NotVulnerable
	ignoredByName := "test-user"
	userID := uuid.New()

	var managedPolicyRef testapi.PolicyRef
	err := managedPolicyRef.FromManagedPolicyRef(testapi.ManagedPolicyRef{
		Id: policyID,
	})
	require.NoError(t, err)

	var appliedPolicy testapi.AppliedPolicy
	err = appliedPolicy.FromIgnore(testapi.Ignore{
		ActionType: testapi.IgnoreActionTypeIgnore,
		Ignore: testapi.IgnoreDetails{
			Reason:     "Test ignore reason",
			Source:     "cli",
			ReasonType: &reasonType,
			IgnoredBy: &testapi.IgnoredBy{
				Name: ignoredByName,
				Id:   userID,
			},
		},
	})
	require.NoError(t, err)

	findings := []*testapi.FindingData{
		{
			Attributes: &testapi.FindingAttributes{
				FindingType: testapi.FindingTypeSca,
				Key:         "test-key",
				Suppression: &testapi.Suppression{
					Status: testapi.SuppressionStatusIgnored,
					Policy: &managedPolicyRef,
				},
			},
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
						Attributes: &testapi.PolicyAttributes{
							Policies: []testapi.Policy{
								{
									Id:            policyID,
									AppliedPolicy: appliedPolicy,
								},
							},
						},
						Id:   uuid.New(),
						Type: "policy",
					},
				},
			},
			Id: func() *openapi_types.UUID { id := uuid.New(); return &id }(),
		},
	}

	issue, err := testapi.NewIssueFromFindings(findings)
	require.NoError(t, err)

	details := issue.GetIgnoreDetails()
	require.NotNil(t, details)

	assert.Equal(t, string(reasonType), details.GetIgnoreReasonType())
	assert.NotNil(t, details.GetIgnoredBy())
	assert.Equal(t, ignoredByName, details.GetIgnoredBy().Name)
}

func TestIssueIgnoreDetails_IgnoreDataMissing(t *testing.T) {
	findings := []*testapi.FindingData{
		{
			Attributes: &testapi.FindingAttributes{
				FindingType: testapi.FindingTypeSca,
				Key:         "test-key",
				Suppression: &testapi.Suppression{
					Status: testapi.SuppressionStatusIgnored,
				},
			},
			Id: func() *openapi_types.UUID { id := uuid.New(); return &id }(),
		},
	}

	issue, err := testapi.NewIssueFromFindings(findings)
	require.NoError(t, err)

	details := issue.GetIgnoreDetails()
	require.NotNil(t, details)

	assert.Empty(t, details.GetIgnoreReasonType())
	assert.Nil(t, details.GetIgnoredBy())
}

func TestIssueIgnoreDetails_NilAttributes(t *testing.T) {
	findings := []*testapi.FindingData{
		{
			Attributes: nil,
			Id:         func() *openapi_types.UUID { id := uuid.New(); return &id }(),
		},
	}

	issue, err := testapi.NewIssueFromFindings(findings)
	require.NoError(t, err)

	details := issue.GetIgnoreDetails()
	assert.Nil(t, details)
}

func TestIssueIgnoreDetails_UninitializedPaths(t *testing.T) {
	findings := []*testapi.FindingData{
		{
			Attributes: &testapi.FindingAttributes{
				FindingType: testapi.FindingTypeSca,
				Key:         "test-key",
				Suppression: &testapi.Suppression{
					Status: testapi.SuppressionStatusIgnored,
				},
			},
			Id: func() *openapi_types.UUID { id := uuid.New(); return &id }(),
		},
	}

	issue, err := testapi.NewIssueFromFindings(findings)
	require.NoError(t, err)

	details := issue.GetIgnoreDetails()
	require.NotNil(t, details)

	// With Status set, isInitialized is true but optional fields are nil
	assert.Equal(t, testapi.SuppressionStatusIgnored, details.GetStatus())
	assert.Nil(t, details.GetCreatedAt())
	assert.Nil(t, details.GetExpiresAt())
	assert.Nil(t, details.GetJustification())
	assert.Nil(t, details.GetPath())
	assert.Nil(t, details.SkipIfFixable())
	assert.True(t, details.IsActive())
}

func TestIssueIgnoreDetails_PolicySearchEdgeCases(t *testing.T) {
	policyID := uuid.New()

	var managedPolicyRef testapi.PolicyRef
	err := managedPolicyRef.FromManagedPolicyRef(testapi.ManagedPolicyRef{
		Id: policyID,
	})
	require.NoError(t, err)

	t.Run("missing relationships", func(t *testing.T) {
		findings := []*testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					FindingType: testapi.FindingTypeSca,
					Key:         "test-key",
					Suppression: &testapi.Suppression{
						Status: testapi.SuppressionStatusIgnored,
						Policy: &managedPolicyRef,
					},
				},
				Relationships: nil,
				Id:            func() *openapi_types.UUID { id := uuid.New(); return &id }(),
			},
		}

		issue, err := testapi.NewIssueFromFindings(findings)
		require.NoError(t, err)

		details := issue.GetIgnoreDetails()
		require.NotNil(t, details)
		assert.NotNil(t, details.GetPolicyID())
	})

	t.Run("non-ignore policy discriminator", func(t *testing.T) {
		var appliedPolicy testapi.AppliedPolicy
		err := appliedPolicy.FromSeverityChange(testapi.SeverityChange{})
		require.NoError(t, err)

		findings := []*testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{
					FindingType: testapi.FindingTypeSca,
					Key:         "test-key",
					Suppression: &testapi.Suppression{
						Status: testapi.SuppressionStatusIgnored,
						Policy: &managedPolicyRef,
					},
				},
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
							Attributes: &testapi.PolicyAttributes{
								Policies: []testapi.Policy{
									{
										Id:            policyID,
										AppliedPolicy: appliedPolicy,
									},
								},
							},
							Id:   uuid.New(),
							Type: "policy",
						},
					},
				},
				Id: func() *openapi_types.UUID { id := uuid.New(); return &id }(),
			},
		}

		issue, err := testapi.NewIssueFromFindings(findings)
		require.NoError(t, err)

		details := issue.GetIgnoreDetails()
		require.NotNil(t, details)
		assert.Empty(t, details.GetIgnoreReasonType())
	})
}
