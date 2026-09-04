package testapi_test

import (
	"encoding/json"
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

func TestIssueIgnoreDetails_GetIgnoreDetails_BasedOnSuppressionStatus(t *testing.T) {
	testCases := []struct {
		name                string
		suppressionStatuses []testapi.SuppressionStatus
		expectedStatus      testapi.SuppressionStatus
		expectNilDetails    bool
	}{
		{name: "single ignored", suppressionStatuses: []testapi.SuppressionStatus{testapi.SuppressionStatusIgnored}, expectedStatus: testapi.SuppressionStatusIgnored},
		{name: "single pending", suppressionStatuses: []testapi.SuppressionStatus{testapi.SuppressionStatusPendingIgnoreApproval}, expectedStatus: testapi.SuppressionStatusPendingIgnoreApproval},
		{name: "single other", suppressionStatuses: []testapi.SuppressionStatus{testapi.SuppressionStatusOther}, expectedStatus: testapi.SuppressionStatusOther},
		{name: "ignored wins over pending and other", suppressionStatuses: []testapi.SuppressionStatus{testapi.SuppressionStatusOther, testapi.SuppressionStatusPendingIgnoreApproval, testapi.SuppressionStatusIgnored}, expectedStatus: testapi.SuppressionStatusIgnored},
		{name: "pending wins over other", suppressionStatuses: []testapi.SuppressionStatus{testapi.SuppressionStatusOther, testapi.SuppressionStatusPendingIgnoreApproval}, expectedStatus: testapi.SuppressionStatusPendingIgnoreApproval},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			findings := make([]*testapi.FindingData, len(tt.suppressionStatuses))
			for i, status := range tt.suppressionStatuses {
				findings[i] = &testapi.FindingData{
					Attributes: &testapi.FindingAttributes{Suppression: &testapi.Suppression{Status: status}},
					Id:         func() *openapi_types.UUID { id := uuid.New(); return &id }(),
				}
			}

			issue, err := testapi.NewIssueFromFindings(findings)
			require.NoError(t, err)

			details := issue.GetIgnoreDetails()
			if tt.expectNilDetails {
				assert.Nil(t, details)
			} else {
				require.NotNil(t, details)
				assert.Equal(t, tt.expectedStatus, details.GetStatus())
			}
		})
	}

	t.Run("empty suppression status yields nil", func(t *testing.T) {
		findings := []*testapi.FindingData{
			{
				Attributes: &testapi.FindingAttributes{Suppression: &testapi.Suppression{}},
				Id:         func() *openapi_types.UUID { id := uuid.New(); return &id }(),
			},
		}

		issue, err := testapi.NewIssueFromFindings(findings)
		require.NoError(t, err)

		details := issue.GetIgnoreDetails()
		assert.Nil(t, details)
	})
}

func TestIssueIgnoreDetails_IsActive(t *testing.T) {
	tests := []struct {
		name            string
		status          testapi.SuppressionStatus
		expectNilDetail bool
		expectActive    bool
	}{
		{"ignored status", testapi.SuppressionStatusIgnored, false, true},
		{"pending status", testapi.SuppressionStatusPendingIgnoreApproval, false, false},
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
				Project *struct {
					Data *struct {
						Id   openapi_types.UUID `json:"id"`
						Type string             `json:"type"`
					} `json:"data,omitempty"`
				} `json:"project,omitempty"`
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
					Project *struct {
						Data *struct {
							Id   openapi_types.UUID `json:"id"`
							Type string             `json:"type"`
						} `json:"data,omitempty"`
					} `json:"project,omitempty"`
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

func TestIssueIgnoreDetails_Reviewer(t *testing.T) {
	const policyID = "90b2fe3f-f811-4447-8f75-e32545d753ea"

	findingWithRule := func(t *testing.T, rule string) *testapi.FindingData {
		t.Helper()
		raw := `{
			"id": "1a1e9f0e-0d1f-4a1e-9f0e-0d1f4a1e9f0e",
			"attributes": {
				"finding_type": "secrets",
				"key": "test-key",
				"suppression": {
					"status": "ignored",
					"policy": {"id": "` + policyID + `"}
				}
			},
			"relationships": {
				"policy": {
					"links": {},
					"data": {
						"id": "2b2e9f0e-0d1f-4a1e-9f0e-0d1f4a1e9f0e",
						"type": "policy",
						"attributes": {
							"policies": [{
								"id": "` + policyID + `",
								"applied_policy": {
									"action_type": "ignore",
									"ignore": {"reason": "Someone is ignoring this", "source": "cli"},
									"rule": ` + rule + `
								}
							}]
						}
					}
				}
			}
		}`

		var finding testapi.FindingData
		require.NoError(t, json.Unmarshal([]byte(raw), &finding))
		return &finding
	}

	const unreviewedRule = `{
		"id": "9a589a14-6ea4-49c5-9fd3-618dc3ebbbd1",
		"name": "",
		"created": "0001-01-01T00:00:00Z",
		"modified": "0001-01-01T00:00:00Z",
		"review": "not-required"
	}`

	t.Run("reviewed rule exposes reviewer and timestamp", func(t *testing.T) {
		finding := findingWithRule(t, `{
			"id": "9a589a14-6ea4-49c5-9fd3-618dc3ebbbd1",
			"name": "",
			"created": "0001-01-01T00:00:00Z",
			"modified": "0001-01-01T00:00:00Z",
			"review": "approved",
			"reviewed_at": "2026-02-06T09:14:22.512Z",
			"reviewed_by": {
				"id": "9c8d2e1f-4a5b-4c6d-8e9f-0a1b2c3d4e5f",
				"name": "Jane Reviewer",
				"email": "jane.reviewer@snyk.io"
			}
		}`)

		details := finding.GetIgnoreDetails()
		require.NotNil(t, details)

		require.NotNil(t, details.GetReviewedOn())
		assert.Equal(t, "2026-02-06T09:14:22.512Z", details.GetReviewedOn().UTC().Format(time.RFC3339Nano))

		require.NotNil(t, details.GetReviewedBy())
		assert.Equal(t, "Jane Reviewer", details.GetReviewedBy().Name)
		require.NotNil(t, details.GetReviewedBy().Email)
		assert.Equal(t, "jane.reviewer@snyk.io", *details.GetReviewedBy().Email)
		assert.Equal(t, uuid.MustParse("9c8d2e1f-4a5b-4c6d-8e9f-0a1b2c3d4e5f"), details.GetReviewedBy().Id)
	})

	t.Run("unreviewed rule exposes neither", func(t *testing.T) {
		details := findingWithRule(t, unreviewedRule).GetIgnoreDetails()
		require.NotNil(t, details)

		assert.Nil(t, details.GetReviewedOn())
		assert.Nil(t, details.GetReviewedBy())
	})

	// A local-policy ignore resolves no policy rule at all, so the accessors must not panic.
	t.Run("local policy suppression exposes neither", func(t *testing.T) {
		raw := `{
			"id": "1a1e9f0e-0d1f-4a1e-9f0e-0d1f4a1e9f0e",
			"attributes": {
				"finding_type": "secrets",
				"key": "test-key",
				"suppression": {"status": "ignored", "policy": "local_policy"}
			}
		}`
		var finding testapi.FindingData
		require.NoError(t, json.Unmarshal([]byte(raw), &finding))

		details := finding.GetIgnoreDetails()
		require.NotNil(t, details)

		assert.Nil(t, details.GetReviewedOn())
		assert.Nil(t, details.GetReviewedBy())
	})
}
