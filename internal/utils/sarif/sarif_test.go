package sarif

import (
	"testing"

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
