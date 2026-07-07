package format

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/diagnosis"
)

func TestFormatTemplate_fullReport(t *testing.T) {
	report := &diagnosis.DoctorReport{
		Summary: diagnosis.Summary{
			Fields: []diagnosis.KeyValue{{Key: "Version", Value: "1.0.0"}},
			Raw:    "Version: 1.0.0",
		},
		Findings: []diagnosis.Finding{
			{Producer: diagnosis.ProducerLogAnalysis, Lines: []int{3}, Kind: diagnosis.KindHTTPError, Severity: diagnosis.SeverityError, Message: "< response [0x2b3cd0a17cc0]: 401 Unauthorized"},
		},
	}

	var buf bytes.Buffer
	err := FormatTemplate(&buf, report)
	require.NoError(t, err)

	rendered := buf.String()
	assert.Contains(t, rendered, "Snyk Doctor Diagnostic Report")
	assert.Contains(t, rendered, "Basic Information")
	assert.Contains(t, rendered, "Version: 1.0.0")
	assert.Contains(t, rendered, "Symptoms")
	assert.Contains(t, rendered, "[LOG-ANALYSIS]")
	assert.Contains(t, rendered, "Lines: 3")
	assert.Contains(t, rendered, "401 Unauthorized")
}

func TestFormatTemplate_noFindings(t *testing.T) {
	report := &diagnosis.DoctorReport{
		Summary: diagnosis.Summary{Raw: "Version: 1.0.0"},
	}

	var buf bytes.Buffer
	require.NoError(t, FormatTemplate(&buf, report))

	rendered := buf.String()
	assert.Contains(t, rendered, "Basic Information")
	assert.Contains(t, rendered, "Symptoms")
}

func TestFormatTemplate_extraProducers(t *testing.T) {
	report := &diagnosis.DoctorReport{
		Findings: []diagnosis.Finding{
			{Producer: diagnosis.ProducerConnectivity, Kind: "dns", Severity: diagnosis.SeverityWarning, Message: "DNS lookup failed"},
			{Producer: diagnosis.ProducerAuth, Kind: "token", Severity: diagnosis.SeverityError, Message: "Token expired"},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, FormatTemplate(&buf, report))

	rendered := buf.String()
	assert.Contains(t, rendered, "Symptoms")
	assert.Contains(t, rendered, "[CONNECTIVITY]")
	assert.Contains(t, rendered, "DNS lookup failed")
	assert.Contains(t, rendered, "[AUTHENTICATION]")
	assert.Contains(t, rendered, "Token expired")
}

func TestFormatJSON_roundTrips(t *testing.T) {
	report := &diagnosis.DoctorReport{
		Summary: diagnosis.Summary{
			Fields: []diagnosis.KeyValue{{Key: "Version", Value: "1.0.0"}},
			Raw:    "Version: 1.0.0",
		},
		Findings: []diagnosis.Finding{
			{Producer: diagnosis.ProducerLogAnalysis, Subject: "L3", Kind: diagnosis.KindHTTPError, Severity: diagnosis.SeverityError, Message: "401 Unauthorized"},
		},
	}

	var buf bytes.Buffer
	require.NoError(t, FormatJSON(&buf, report))

	var decoded diagnosis.DoctorReport
	require.NoError(t, json.Unmarshal(buf.Bytes(), &decoded))
	assert.Equal(t, "Version", decoded.Summary.Fields[0].Key)
	assert.Len(t, decoded.Findings, 1)
	assert.Equal(t, diagnosis.KindHTTPError, decoded.Findings[0].Kind)
}
