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
	isIgnored, currentSuppression := GetIgnoreDetails([]sarif.Suppression{
		{
			Status: sarif.Accepted,
		}})

	assert.True(t, isIgnored)
	assert.Equal(t, currentSuppression.Status, sarif.Accepted)

	isIgnored, currentSuppression = GetIgnoreDetails([]sarif.Suppression{
		{
			Status: sarif.Rejected,
		}})

	assert.False(t, isIgnored)
	assert.Equal(t, currentSuppression.Status, sarif.Rejected)

	isIgnored, currentSuppression = GetIgnoreDetails([]sarif.Suppression{
		{
			Status: sarif.UnderReview,
		}})

	assert.False(t, isIgnored)
	assert.Equal(t, currentSuppression.Status, sarif.UnderReview)
}
