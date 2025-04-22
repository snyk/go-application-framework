package sarif

import (
	"testing"

	"github.com/snyk/code-client-go/sarif"
	"github.com/stretchr/testify/assert"
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

func TestIsIgnored(t *testing.T) {
	isIgnored, suppression := GetIgnoreDetails([]sarif.Suppression{
		{
			Status: sarif.Accepted,
		}})

	assert.False(t, isIgnored)
	assert.NotNil(t, suppression)
	assert.Equal(t, sarif.Accepted, suppression.Status)

	isIgnored, suppression = GetIgnoreDetails([]sarif.Suppression{
		{
			Status: sarif.Rejected,
		}})

	assert.False(t, isIgnored)
	assert.NotNil(t, suppression)
	assert.Equal(t, sarif.Rejected, suppression.Status)

	isIgnored, suppression = GetIgnoreDetails([]sarif.Suppression{
		{
			Status: sarif.UnderReview,
		}})

	assert.False(t, isIgnored)
	assert.NotNil(t, suppression)
	assert.Equal(t, sarif.UnderReview, suppression.Status)

	isIgnored, suppression = GetIgnoreDetails([]sarif.Suppression{})

	assert.False(t, isIgnored)
	assert.Nil(t, suppression)
}

// TestSuppressionPrecedence tests the precedence logic when multiple suppressions exist.
// The precedence order is: Accepted > UnderReview > Rejected.
// An empty Status is treated as Accepted.
func TestSuppressionPrecedence(t *testing.T) {
	// Test precedence: Accepted > UnderReview > Rejected
	isIgnored, suppression := GetIgnoreDetails([]sarif.Suppression{
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

	assert.False(t, isIgnored)
	assert.NotNil(t, suppression)
	assert.Equal(t, sarif.Accepted, suppression.Status)

	// Test precedence: Empty status is treated as Accepted
	isIgnored, suppression = GetIgnoreDetails([]sarif.Suppression{
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

	assert.True(t, isIgnored)
	assert.NotNil(t, suppression)
	assert.Equal(t, sarif.SuppresionStatus(""), suppression.Status)

	// Test precedence when Accepted is missing: UnderReview > Rejected
	isIgnored, suppression = GetIgnoreDetails([]sarif.Suppression{
		{
			Status: sarif.Rejected,
		},
		{
			Status: sarif.UnderReview,
		},
	})

	assert.False(t, isIgnored)
	assert.NotNil(t, suppression)
	assert.Equal(t, sarif.UnderReview, suppression.Status)

	// Test precedence with Accepted having higher priority even if not first in the list
	isIgnored, suppression = GetIgnoreDetails([]sarif.Suppression{
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

	assert.False(t, isIgnored)
	assert.NotNil(t, suppression)
	assert.Equal(t, sarif.Accepted, suppression.Status)

	// Test when only rejected suppressions are present
	isIgnored, suppression = GetIgnoreDetails([]sarif.Suppression{
		{
			Status: sarif.Rejected,
		},
	})

	assert.False(t, isIgnored)
	assert.NotNil(t, suppression)
	assert.Equal(t, sarif.Rejected, suppression.Status)
}
