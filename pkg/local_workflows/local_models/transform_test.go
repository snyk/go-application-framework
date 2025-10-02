package local_models

import (
	"testing"

	"github.com/snyk/code-client-go/sarif"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/utils"
)

func Test_mapSuppressions(t *testing.T) {
	validUUID1 := "3b3b7c0c-7b1e-4b0e-8b0a-0b0b0b0b0b0b"
	validUUID2 := "4c4c8d1d-8c2f-5c1f-9c1b-1c1c1c1c1c1c"
	expirationDate := "2024-12-31T23:59:59Z"

	tests := []struct {
		name         string
		inputResult  sarif.Result
		expectedSupp *TypesSuppression
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
			name: "single suppression with no status field - accepted",
			inputResult: sarif.Result{
				Suppressions: []sarif.Suppression{
					{
						Guid:          validUUID1,
						Justification: "Test justification",
						Properties: sarif.SuppressionProperties{
							Category:  "testCategory",
							IgnoredOn: "2023-01-01T00:00:00Z",
							IgnoredBy: sarif.IgnoredBy{Name: "User"},
						},
					},
				},
			},
			expectedSupp: &TypesSuppression{
				Id: &validUUID1,
				Details: &TypesSuppressionDetails{
					Category:   "testCategory",
					Expiration: nil,
					IgnoredOn:  "2023-01-01T00:00:00Z",
					IgnoredBy: TypesUser{
						Name:  "User",
						Email: "",
					},
				},
				Justification: utils.Ptr("Test justification"),
				Status:        TypesSuppressionStatus(sarif.Accepted),
			},
		},
		{
			name: "single suppression with accepted status field",
			inputResult: sarif.Result{
				Suppressions: []sarif.Suppression{
					{
						Guid:          validUUID2,
						Justification: "Full details justification",
						Status:        sarif.Accepted,
						Properties: sarif.SuppressionProperties{
							Category:   "fullCategory",
							Expiration: &expirationDate,
							IgnoredOn:  "2023-02-01T00:00:00Z",
							IgnoredBy:  sarif.IgnoredBy{Name: "Admin User", Email: utils.Ptr("admin@example.com")},
						},
					},
				},
			},
			expectedSupp: &TypesSuppression{
				Id: &validUUID2,
				Details: &TypesSuppressionDetails{
					Category:   "fullCategory",
					Expiration: &expirationDate,
					IgnoredOn:  "2023-02-01T00:00:00Z",
					IgnoredBy: TypesUser{
						Name:  "Admin User",
						Email: "admin@example.com",
					},
				},
				Justification: utils.Ptr("Full details justification"),
				Status:        TypesSuppressionStatus(sarif.Accepted),
			},
		},
		{
			name: "suppression with accepted status field but without id",
			inputResult: sarif.Result{
				Suppressions: []sarif.Suppression{
					{
						Justification: "Missing GUID test",
						Status:        sarif.Accepted,
						Properties: sarif.SuppressionProperties{
							Category:  "missingGUIDtest",
							IgnoredOn: "2023-03-01T00:00:00Z",
							IgnoredBy: sarif.IgnoredBy{Name: "Tester"},
						},
					},
				},
			},
			expectedSupp: &TypesSuppression{
				Id: nil,
				Details: &TypesSuppressionDetails{
					Category:   "missingGUIDtest",
					Expiration: nil,
					IgnoredOn:  "2023-03-01T00:00:00Z",
					IgnoredBy: TypesUser{
						Name:  "Tester",
						Email: "",
					},
				},
				Justification: utils.Ptr("Missing GUID test"),
				Status:        TypesSuppressionStatus(sarif.Accepted),
			},
		},
		{
			name: "multiple suppressions - picking 'accepted' over 'rejected'",
			inputResult: sarif.Result{
				Suppressions: []sarif.Suppression{
					{Guid: validUUID1, Justification: "Rejected", Status: sarif.Rejected, Properties: sarif.SuppressionProperties{Category: "cat1"}},
					{Guid: validUUID2, Justification: "Accepted", Status: sarif.Accepted, Properties: sarif.SuppressionProperties{Category: "cat2"}},
				},
			},
			expectedSupp: &TypesSuppression{
				Id:            &validUUID2,
				Justification: utils.Ptr("Accepted"),
				Details: &TypesSuppressionDetails{
					Category:   "cat2",
					Expiration: nil,
					IgnoredOn:  "",
					IgnoredBy:  TypesUser{Name: "", Email: ""},
				},
				Status: TypesSuppressionStatus(sarif.Accepted),
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
				Id:            &validUUID1,
				Justification: utils.Ptr("Under review"),
				Details: &TypesSuppressionDetails{
					Category:   "reviewCategory",
					Expiration: nil,
					IgnoredOn:  "",
					IgnoredBy:  TypesUser{Name: "", Email: ""},
				},
				Status: TypesSuppressionStatus(sarif.UnderReview),
			},
		},
		{
			name: "suppression with 'rejected' status",
			inputResult: sarif.Result{
				Suppressions: []sarif.Suppression{
					{Guid: validUUID1, Justification: "Rejected", Status: sarif.Rejected, Properties: sarif.SuppressionProperties{Category: "rejectedCategory"}},
				},
			},
			expectedSupp: &TypesSuppression{
				Id:            &validUUID1,
				Justification: utils.Ptr("Rejected"),
				Details: &TypesSuppressionDetails{
					Category:   "rejectedCategory",
					Expiration: nil,
					IgnoredOn:  "",
					IgnoredBy:  TypesUser{Name: "", Email: ""},
				},
				Status: TypesSuppressionStatus(sarif.Rejected),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualSupp := mapSuppressions(tt.inputResult)
			assert.Equal(t, tt.expectedSupp, actualSupp)
		})
	}
}
