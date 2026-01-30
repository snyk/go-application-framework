package sarif

import (
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/code-client-go/sarif"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/apiclients/mocks"
	"github.com/snyk/go-application-framework/pkg/apiclients/testapi"
)

func TestSeverityLevelConverter(t *testing.T) {
	//"low", "medium", "high", "critical"
	expectedSeverities := map[string]string{
		"low":      "note",
		"medium":   "warning",
		"high":     "error",
		"critical": "error",
	}

	for severity, level := range expectedSeverities {
		actualLevel := SeverityToSarifLevel(severity)
		assert.Equal(t, level, actualLevel)

		actualSeverity := SarifLevelToSeverity(actualLevel)

		// handling ambiguous mapping of high and critical to error
		if severity == "critical" {
			severity = "high"
		}

		assert.Equal(t, severity, actualSeverity)
	}
}

func TestConvertTypeToDriverName(t *testing.T) {
	expected := map[string]string{
		"sast":      "SnykCode",
		"iac":       "Snyk IaC",
		"container": "Snyk Container",
		"sca":       "Snyk Open Source",
		"random":    "Snyk Open Source",
	}

	for input, expectedOutput := range expected {
		actualOutput := ConvertTypeToDriverName(input)
		assert.Equal(t, expectedOutput, actualOutput)
	}
}

func TestHasSuppressionInStatus(t *testing.T) {
	suppressions := []sarif.Suppression{
		{
			Status: sarif.Accepted,
		}}
	assert.True(t, IsHighestSuppressionStatus(suppressions, sarif.Accepted))

	suppressions = []sarif.Suppression{
		{
			Status: sarif.UnderReview,
		}}
	assert.True(t, IsHighestSuppressionStatus(suppressions, sarif.UnderReview))

	suppressions = []sarif.Suppression{
		{
			Status: sarif.Rejected,
		}}

	assert.True(t, IsHighestSuppressionStatus(suppressions, sarif.Rejected))

	suppressions = []sarif.Suppression{
		{
			Status: "invalidState",
		}}

	assert.False(t, IsHighestSuppressionStatus(suppressions, sarif.Accepted))
}

// TestSuppressionPrecedence tests the precedence logic when multiple suppressions exist.
// The precedence order is: Accepted > UnderReview > Rejected.
// An empty Status is treated as Accepted.
func TestSuppressionPrecedence(t *testing.T) {
	// Test precedence: Accepted > UnderReview > Rejected
	suppression, suppressionStatus := GetHighestSuppression([]sarif.Suppression{
		{
			Status: sarif.Rejected,
		},
		{
			Status: sarif.Accepted,
		},
		{
			Status: sarif.UnderReview,
		},
	})

	assert.NotNil(t, suppression)
	assert.Equal(t, sarif.Accepted, suppressionStatus)

	// Test precedence: Empty status is treated as Accepted
	suppression, suppressionStatus = GetHighestSuppression([]sarif.Suppression{
		{
			Status: sarif.Rejected,
		},
		{
			Status: "",
		},
		{
			Status: sarif.UnderReview,
		},
	})

	assert.NotNil(t, suppression)
	assert.Equal(t, sarif.Accepted, suppressionStatus)

	// Test precedence when Accepted is missing: UnderReview > Rejected
	suppression, suppressionStatus = GetHighestSuppression([]sarif.Suppression{
		{
			Status: sarif.Rejected,
		},
		{
			Status: sarif.UnderReview,
		},
	})

	assert.NotNil(t, suppression)
	assert.Equal(t, sarif.UnderReview, suppressionStatus)

	// Test precedence with Accepted having higher priority even if not first in the list
	suppression, suppressionStatus = GetHighestSuppression([]sarif.Suppression{
		{
			Status: sarif.UnderReview,
		},
		{
			Status: sarif.Accepted,
		},
		{
			Status: sarif.Rejected,
		},
	})

	assert.NotNil(t, suppression)
	assert.Equal(t, sarif.Accepted, suppressionStatus)

	// Test when only rejected suppressions are present
	suppression, suppressionStatus = GetHighestSuppression([]sarif.Suppression{
		{
			Status: sarif.Rejected,
		},
	})

	assert.NotNil(t, suppression)
	assert.Equal(t, sarif.Rejected, suppressionStatus)
}

func TestBuildFixFromIssue(t *testing.T) {
	t.Run("returns nil when isFixable is not set", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIssue := mocks.NewMockIssue(ctrl)
		mockIssue.EXPECT().GetData(testapi.DataKeyIsFixable).Return(nil, false)

		fix := BuildFixFromIssue(mockIssue)
		assert.Nil(t, fix)
	})

	t.Run("returns nil when isFixable is false", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIssue := mocks.NewMockIssue(ctrl)
		mockIssue.EXPECT().GetData(testapi.DataKeyIsFixable).Return(false, true)

		fix := BuildFixFromIssue(mockIssue)
		assert.Nil(t, fix)
	})

	t.Run("returns nil when no findings", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockIssue := mocks.NewMockIssue(ctrl)
		mockIssue.EXPECT().GetData(testapi.DataKeyIsFixable).Return(true, true)
		mockIssue.EXPECT().GetFindings().Return(nil)

		fix := BuildFixFromIssue(mockIssue)
		assert.Nil(t, fix)
	})

	t.Run("returns upgrade fix when upgrade advice exists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		upgradeAdvice := testapi.UpgradePackageAdvice{
			UpgradePaths: []testapi.UpgradePath{
				{
					DependencyPath: []testapi.Package{
						{Name: "root", Version: "1.0.0"},
						{Name: "lodash", Version: "4.17.21"},
					},
				},
			},
		}

		fixAction := &testapi.FixAction{}
		err := fixAction.FromUpgradePackageAdvice(upgradeAdvice)
		assert.NoError(t, err)

		finding := createFindingWithFixAction(t, fixAction)

		mockIssue := mocks.NewMockIssue(ctrl)
		mockIssue.EXPECT().GetData(testapi.DataKeyIsFixable).Return(true, true)
		mockIssue.EXPECT().GetFindings().Return([]*testapi.FindingData{finding})

		fix := BuildFixFromIssue(mockIssue)
		assert.NotNil(t, fix)
		assert.Equal(t, "Upgrade to lodash@4.17.21", fix["description"])
		assert.Equal(t, "lodash@4.17.21", fix["packageVersion"])
	})

	t.Run("returns pin fix when pin advice exists", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		pinAdvice := testapi.PinPackageAdvice{
			PackageName: "lodash",
			PinVersion:  "4.17.21",
		}

		fixAction := &testapi.FixAction{}
		err := fixAction.FromPinPackageAdvice(pinAdvice)
		assert.NoError(t, err)

		finding := createFindingWithFixAction(t, fixAction)

		mockIssue := mocks.NewMockIssue(ctrl)
		mockIssue.EXPECT().GetData(testapi.DataKeyIsFixable).Return(true, true)
		mockIssue.EXPECT().GetFindings().Return([]*testapi.FindingData{finding})

		fix := BuildFixFromIssue(mockIssue)
		assert.NotNil(t, fix)
		assert.Equal(t, "Upgrade to lodash@4.17.21", fix["description"])
		assert.Equal(t, "lodash@4.17.21", fix["packageVersion"])
	})
}

func createFindingWithFixAction(t *testing.T, fixAction *testapi.FixAction) *testapi.FindingData {
	t.Helper()

	findingJSON := `{
		"relationships": {
			"fix": {
				"data": {
					"id": "00000000-0000-0000-0000-000000000000",
					"type": "fixes",
					"attributes": {}
				}
			}
		}
	}`
	var finding testapi.FindingData
	err := json.Unmarshal([]byte(findingJSON), &finding)
	assert.NoError(t, err)

	finding.Relationships.Fix.Data.Attributes = &testapi.FixAttributes{
		Action: fixAction,
	}
	return &finding
}
