package diagnosis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func analyzeFixture(t *testing.T, name string) *DoctorReport {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	report, err := Analyze(context.Background(), strings.NewReader(string(raw)), DefaultLogChecks())
	require.NoError(t, err)
	return report
}

func TestAnalyze_emptyConfigFixture(t *testing.T) {
	report := analyzeFixture(t, "empty-config.logs")

	// Summary should contain environment fields.
	assert.NotEmpty(t, report.Summary.Fields)
	assert.Contains(t, report.Summary.Raw, "Version:")
	assert.Contains(t, report.Summary.Raw, "API:")

	// Should have log-analysis findings (HTTP errors, CLI errors).
	var hasHTTP, hasCLI bool
	for _, f := range report.Findings {
		if f.Source == SourceLogAnalysis && f.Kind == KindHTTPError {
			hasHTTP = true
		}
		if f.Source == SourceLogAnalysis && f.Kind == KindCLIError {
			hasCLI = true
		}
	}
	assert.True(t, hasHTTP, "expected HTTP error finding")
	assert.True(t, hasCLI, "expected CLI error finding")

	// Should have result findings (exit code, error code).
	var hasExit, hasErrorCode bool
	for _, f := range report.Findings {
		if f.Source == SourceCLIResult && f.Kind == KindExitCode {
			hasExit = true
		}
		if f.Source == SourceCLIResult && f.Kind == KindErrorCode {
			hasErrorCode = true
		}
	}
	assert.True(t, hasExit, "expected exit code finding")
	assert.True(t, hasErrorCode, "expected error code finding")
}

func TestAnalyze_wrongEnvironmentFixture(t *testing.T) {
	report := analyzeFixture(t, "wrong-environment.logs")

	assert.Contains(t, report.Summary.Raw, "Version:")
	assert.Contains(t, report.Summary.Raw, "tok11111")

	var hasExit bool
	for _, f := range report.Findings {
		if f.Kind == KindExitCode {
			hasExit = true
		}
	}
	assert.True(t, hasExit)

	// 401 Unauthorized should appear as HTTP error.
	var hasHTTP bool
	for _, f := range report.Findings {
		if f.Kind == KindHTTPError && strings.Contains(f.Message, "401 Unauthorized") {
			hasHTTP = true
		}
	}
	assert.True(t, hasHTTP)
}

func TestAnalyze_noHeaderFooter(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - Using log level: debug",
		"2026-06-10T13:10:38Z main - < response [0x2b3cd0a17cc0]: 500 Internal Server Error",
		"2026-06-10T13:10:38Z main - < error: something broke",
	}, "\n")

	report, err := Analyze(context.Background(), strings.NewReader(log), DefaultLogChecks())
	require.NoError(t, err)

	assert.Empty(t, report.Summary.Fields)
	require.Len(t, report.Findings, 2)
	assert.Equal(t, KindHTTPError, report.Findings[0].Kind)
	assert.Equal(t, KindCLIError, report.Findings[1].Kind)
}

func TestAnalyze_exitCodeSeverity(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - ------------ Summary ------------",
		"Exit Code:             0",
	}, "\n")

	report, err := Analyze(context.Background(), strings.NewReader(log), DefaultLogChecks())
	require.NoError(t, err)

	require.Len(t, report.Findings, 1)
	assert.Equal(t, KindExitCode, report.Findings[0].Kind)
	assert.Equal(t, SeverityInfo, report.Findings[0].Severity)
}

func TestAnalyze_exitCodeNonZeroIsSeverityError(t *testing.T) {
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - ------------ Summary ------------",
		"Exit Code:             2",
	}, "\n")

	report, err := Analyze(context.Background(), strings.NewReader(log), DefaultLogChecks())
	require.NoError(t, err)

	require.Len(t, report.Findings, 1)
	assert.Equal(t, SeverityError, report.Findings[0].Severity)
}
