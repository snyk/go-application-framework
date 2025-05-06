package local_models

import (
	"testing"

	"github.com/google/uuid"
	"github.com/snyk/code-client-go/sarif"
	"github.com/stretchr/testify/assert"
)

func stringPtr(s string) *string {
	return &s
}

func Test_mapSuppressions(t *testing.T) {
	validUUID1 := "3b3b7c0c-7b1e-4b0e-8b0a-0b0b0b0b0b0b"
	validUUID2 := "4c4c8d1d-8c2f-5c1f-9c1b-1c1c1c1c1c1c"

	tests := []struct {
		name            string
		inputResult     sarif.Result
		expectedSupp    *TypesSuppression
		expectPanic     bool
	}{
		{
			name:         "no suppressions in result",
			inputResult:  sarif.Result{Suppressions: nil},
			expectedSupp: nil,
		},
		{
			name:         "empty list of suppressions in result",
			inputResult:  sarif.Result{Suppressions: []sarif.Suppression{}},
			expectedSupp: nil,
		},
		{
			name: "single suppression with valid GUID and minimal details",
			inputResult: sarif.Result{
				Suppressions: []sarif.Suppression{
					{
						Guid:          validUUID1,
						Justification: "Test justification",
						Status:        sarif.Accepted,
						Properties: sarif.SuppressionProperties{
							Category:  "testCategory",
							IgnoredOn: "2023-01-01T00:00:00Z",
							IgnoredBy: sarif.IgnoredBy{Name: "User"},
						},
					},
				},
			},
			expectedSupp: &TypesSuppression{
				Id: uuid.MustParse(validUUID1),
				Details: &TypesSuppressionDetails{
					Category:   "testCategory",
					Expiration: "",
					IgnoredOn:  "2023-01-01T00:00:00Z",
					IgnoredBy: TypesUser{
						Name:  "User",
						Email: "",
					},
				},
				Justification: stringPtr("Test justification"),
				Status:        TypesSuppressionStatus(sarif.Accepted),
			},
		},
		{
			name: "single suppression with valid GUID and full details",
			inputResult: sarif.Result{
				Suppressions: []sarif.Suppression{
					{
						Guid:          validUUID2,
						Justification: "Full details justification",
						Status:        sarif.Accepted,
						Properties: sarif.SuppressionProperties{
							Category:   "fullCategory",
							Expiration: stringPtr("2024-12-31T23:59:59Z"),
							IgnoredOn:  "2023-02-01T00:00:00Z",
							IgnoredBy:  sarif.IgnoredBy{Name: "Admin User", Email: stringPtr("admin@example.com")},
						},
					},
				},
			},
			expectedSupp: &TypesSuppression{
				Id: uuid.MustParse(validUUID2),
				Details: &TypesSuppressionDetails{
					Category:   "fullCategory",
					Expiration: "2024-12-31T23:59:59Z",
					IgnoredOn:  "2023-02-01T00:00:00Z",
					IgnoredBy: TypesUser{
						Name:  "Admin User",
						Email: "admin@example.com",
					},
				},
				Justification: stringPtr("Full details justification"),
				Status:        TypesSuppressionStatus(sarif.Accepted),
			},
		},
		{
			name: "suppression with invalid GUID causes panic",
			inputResult: sarif.Result{
				Suppressions: []sarif.Suppression{
					{
						Guid:   "not-a-valid-uuid",
						Status: sarif.Accepted,
					},
				},
			},
			expectPanic:   true,
		},
		{
			name: "multiple suppressions, GetHighestSuppression picks 'accepted' over 'rejected'",
			inputResult: sarif.Result{
				Suppressions: []sarif.Suppression{
					{Guid: validUUID1, Justification: "Rejected", Status: sarif.Rejected, Properties: sarif.SuppressionProperties{Category: "cat1"}},
					{Guid: validUUID2, Justification: "Accepted", Status: sarif.Accepted, Properties: sarif.SuppressionProperties{Category: "cat2"}},
				},
			},
			expectedSupp: &TypesSuppression{
				Id:            uuid.MustParse(validUUID2),
				Details:       &TypesSuppressionDetails{Category: "cat2"},
				Justification: stringPtr("Accepted"),
				Status:        TypesSuppressionStatus(sarif.Accepted),
			},
		},
		{
			name: "suppression with 'underReview' status",
			inputResult: sarif.Result{
				Suppressions: []sarif.Suppression{
					{Guid: validUUID1, Justification: "Under review", Status: sarif.UnderReview, Properties: sarif.SuppressionProperties{Category: "reviewCategory"}},
				},
			},
			expectedSupp: &TypesSuppression{
				Id:            uuid.MustParse(validUUID1),
				Details:       &TypesSuppressionDetails{Category: "reviewCategory"},
				Justification: stringPtr("Under review"),
				Status:        TypesSuppressionStatus(sarif.UnderReview),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.expectPanic {
				assert.Panics(t, func() {
					mapSuppressions(tt.inputResult)
				}, "Expected a panic due to invalid GUID")
			} else {
				actualSupp := mapSuppressions(tt.inputResult)
				assert.Equal(t, tt.expectedSupp, actualSupp)
			}
		})
	}
}