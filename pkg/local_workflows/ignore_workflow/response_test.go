package ignore_workflow

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/snyk/code-client-go/sarif"
	"github.com/stretchr/testify/assert"

	v20241015 "github.com/snyk/go-application-framework/internal/api/policy/2024-10-15"
)

func TestPolicyReviewToSarifStatus(t *testing.T) {
	testCases := []struct {
		name     string
		review   v20241015.PolicyReview
		expected sarif.SuppresionStatus
	}{
		{
			name:     "Pending review",
			review:   v20241015.PolicyReviewPending,
			expected: sarif.UnderReview,
		},
		{
			name:     "Rejected review",
			review:   v20241015.PolicyReviewRejected,
			expected: sarif.Rejected,
		},
		{
			name:     "Approved review",
			review:   v20241015.PolicyReviewApproved,
			expected: sarif.Accepted,
		},
		{
			name:     "NotRequired review",
			review:   v20241015.PolicyReviewNotRequired,
			expected: sarif.Accepted,
		},
		{
			name:     "Unknown review",
			review:   "unknown",
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := policyReviewToSarifStatus(tc.review)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestPolicyResponseToSarifSuppression(t *testing.T) {
	t.Run("When policyResponse is nil", func(t *testing.T) {
		result := policyResponseToSarifSuppression(nil)
		assert.Nil(t, result)
	})

	expectedUserName := "Test User"
	expectedEmail := "test@example.com"
	t.Run("When policyResponse has all fields", func(t *testing.T) {
		reason := "security exception"
		now := time.Now()
		expires := now.Add(24 * time.Hour)
		id := uuid.New()
		ignoreType := v20241015.WontFix
		policyResponse := &v20241015.PolicyResponse{
			Id: id,
			Attributes: v20241015.PolicyResponseAttributes{
				CreatedAt: now,
				CreatedBy: &v20241015.Principal{
					Name:  expectedUserName,
					Email: stringPtr(expectedEmail),
				},
				Action: v20241015.PolicyActionIgnore{
					Data: v20241015.PolicyActionIgnoreData{
						Reason:     &reason,
						Expires:    &expires,
						IgnoreType: ignoreType,
					},
				},
				Review: v20241015.PolicyReviewApproved,
			},
		}

		result := policyResponseToSarifSuppression(policyResponse)

		assert.NotNil(t, result)
		assert.Equal(t, id.String(), result.Guid)
		assert.Equal(t, reason, result.Justification)
		assert.NotNil(t, result.Properties.Expiration)
		assert.Equal(t, expires.Format(time.RFC3339), *result.Properties.Expiration)
		assert.Equal(t, now.Format(time.RFC3339), result.Properties.IgnoredOn)
		assert.Equal(t, expectedUserName, result.Properties.IgnoredBy.Name)
		assert.Equal(t, expectedEmail, *result.Properties.IgnoredBy.Email)
		assert.Equal(t, string(ignoreType), string(result.Properties.Category))
		assert.Equal(t, sarif.Accepted, result.Status)
	})

	t.Run("When policyResponse has no expiration", func(t *testing.T) {
		reason := "security exception"
		now := time.Now()
		id := uuid.New()

		policyResponse := &v20241015.PolicyResponse{
			Id: id,
			Attributes: v20241015.PolicyResponseAttributes{
				CreatedAt: now,
				CreatedBy: &v20241015.Principal{
					Name:  expectedUserName,
					Email: stringPtr(expectedEmail),
				},
				Action: v20241015.PolicyActionIgnore{
					Data: v20241015.PolicyActionIgnoreData{
						Reason:  &reason,
						Expires: nil,
					},
				},
				Review: v20241015.PolicyReviewApproved,
			},
		}

		result := policyResponseToSarifSuppression(policyResponse)

		assert.NotNil(t, result)
		assert.Equal(t, id.String(), result.Guid)
		assert.Equal(t, reason, result.Justification)
		assert.Nil(t, result.Properties.Expiration)
		assert.Equal(t, now.Format(time.RFC3339), result.Properties.IgnoredOn)
		assert.Equal(t, expectedUserName, result.Properties.IgnoredBy.Name)
		assert.Equal(t, expectedEmail, *result.Properties.IgnoredBy.Email)
		assert.Equal(t, sarif.Accepted, result.Status)
	})

	t.Run("Different policy review status", func(t *testing.T) {
		reason := "security exception"
		now := time.Now()
		id := uuid.New()

		testCases := []struct {
			name     string
			review   v20241015.PolicyReview
			expected sarif.SuppresionStatus
		}{
			{
				name:     "Pending review",
				review:   v20241015.PolicyReviewPending,
				expected: sarif.UnderReview,
			},
			{
				name:     "Rejected review",
				review:   v20241015.PolicyReviewRejected,
				expected: sarif.Rejected,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				policyResponse := &v20241015.PolicyResponse{
					Id: id,
					Attributes: v20241015.PolicyResponseAttributes{
						CreatedAt: now,
						CreatedBy: &v20241015.Principal{
							Name:  expectedUserName,
							Email: stringPtr(expectedEmail),
						},
						Action: v20241015.PolicyActionIgnore{
							Data: v20241015.PolicyActionIgnoreData{
								Reason:  &reason,
								Expires: nil,
							},
						},
						Review: tc.review,
					},
				}

				result := policyResponseToSarifSuppression(policyResponse)

				assert.NotNil(t, result)
				assert.Equal(t, tc.expected, result.Status)
			})
		}
	})
}

// Helper function to create string pointers
func stringPtr(s string) *string {
	return &s
}
