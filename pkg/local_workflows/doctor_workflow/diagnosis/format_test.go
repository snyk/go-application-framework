package diagnosis

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatText_fullReport(t *testing.T) {
	report := &DoctorReport{
		Summary: Summary{
			Fields: []KeyValue{{Key: "Version", Value: "1.0.0"}},
			Raw:    "Version: 1.0.0",
		},
		Findings: []Finding{
			{Source: SourceLogAnalysis, Subject: "L3", Kind: KindHTTPError, Severity: SeverityError, Message: "< response [0x2b3cd0a17cc0]: 401 Unauthorized"},
		},
		Result: strings.Join([]string{
			"------------ Errors ------------",
			"ERROR:                 Authentication error (SNYK-0005)",
			"  Description:",
			"                       Authentication credentials not recognized.",
			"  Links:",
			"                       https://docs.snyk.io/scan-with-snyk/error-catalog#snyk-0005",
			"Exit Code:             2",
		}, "\n"),
	}

	var buf bytes.Buffer
	err := FormatText(&buf, report)
	require.NoError(t, err)

	rendered := buf.String()
	assert.Contains(t, rendered, "Snyk Doctor Diagnostic Report")
	assert.Contains(t, rendered, "Environment")
	assert.Contains(t, rendered, "Version: 1.0.0")
	assert.Contains(t, rendered, "Notable Events")
	assert.Contains(t, rendered, "L3 [http-error]")
	assert.Contains(t, rendered, "401 Unauthorized")
	assert.Contains(t, rendered, "Result")
	// The full errors block is preserved verbatim, not just the code line.
	assert.Contains(t, rendered, "Authentication error (SNYK-0005)")
	assert.Contains(t, rendered, "Description:")
	assert.Contains(t, rendered, "https://docs.snyk.io/scan-with-snyk/error-catalog#snyk-0005")
	assert.Contains(t, rendered, "Exit Code:             2")
}

func TestFormatText_noFindings(t *testing.T) {
	report := &DoctorReport{
		Summary: Summary{Raw: "Version: 1.0.0"},
	}

	var buf bytes.Buffer
	require.NoError(t, FormatText(&buf, report))

	rendered := buf.String()
	assert.Contains(t, rendered, "No failing requests or CLI error entries found in the log body.")
	assert.Contains(t, rendered, "(not found in the provided log)")
}

func TestFormatText_noSummary(t *testing.T) {
	report := &DoctorReport{}

	var buf bytes.Buffer
	require.NoError(t, FormatText(&buf, report))

	rendered := buf.String()
	assert.Contains(t, rendered, "Environment")
	assert.Contains(t, rendered, "(not found in the provided log)")
}

func TestFormatJSON_roundTrips(t *testing.T) {
	report := &DoctorReport{
		Summary: Summary{
			Fields: []KeyValue{{Key: "Version", Value: "1.0.0"}},
			Raw:    "Version: 1.0.0",
		},
		Findings: []Finding{
			{Source: SourceLogAnalysis, Subject: "L3", Kind: KindHTTPError, Severity: SeverityError, Message: "401 Unauthorized"},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, FormatJSON(&buf, report))

	var decoded DoctorReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	assert.Equal(t, "Version", decoded.Summary.Fields[0].Key)
	assert.Len(t, decoded.Findings, 1)
	assert.Equal(t, KindHTTPError, decoded.Findings[0].Kind)
}
