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

	// Should have log-analysis findings: HTTP errors (now correlated) + CLI errors.
	var hasHTTP, hasCLI bool
	for _, f := range report.Findings {
		if f.Producer == ProducerLogAnalysis && f.Kind == KindCorrelation {
			hasHTTP = true
		}
		if f.Producer == ProducerLogAnalysis && f.Kind == KindCLIError {
			hasCLI = true
		}
	}
	assert.True(t, hasHTTP, "expected correlated HTTP error finding")
	assert.True(t, hasCLI, "expected CLI error finding")

	// Should have result findings (exit code, error code).
	var hasExit, hasErrorCode bool
	for _, f := range report.Findings {
		if f.Producer == ProducerCLIResult && f.Kind == KindExitCode {
			hasExit = true
		}
		if f.Producer == ProducerCLIResult && f.Kind == KindErrorCode {
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

	// 401 Unauthorized should appear as a correlated HTTP finding.
	var hasHTTP bool
	for _, f := range report.Findings {
		if f.Kind == KindCorrelation && strings.Contains(f.Message, "401 Unauthorized") {
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
	// DefaultLogChecks runs correlation first, then CLI error events.
	assert.Equal(t, KindCorrelation, report.Findings[0].Kind)
	assert.Contains(t, report.Findings[0].Message, "500 Internal Server Error")
	assert.Equal(t, KindCLIError, report.Findings[1].Kind)
}

func TestAnalyze_resultPreservesFullErrorBlock(t *testing.T) {
	// Regression: the result section must keep the whole errors block (Description,
	// Links, ...), not just the ERROR/Exit Code lines lifted into findings.
	log := strings.Join([]string{
		"2026-06-10T13:10:38Z main - < response [0x1]: 401 Unauthorized",
		"2026-06-10T13:10:38Z main - ------------ Summary ------------",
		"2026-06-10T13:10:38Z main - ------------ Errors ------------",
		"2026-06-10T13:10:38Z main - ERROR:                 Authentication error (SNYK-0005)",
		"2026-06-10T13:10:38Z main -   Description:",
		"2026-06-10T13:10:38Z main -                        Authentication credentials not recognized.",
		"2026-06-10T13:10:38Z main -   Links:",
		"2026-06-10T13:10:38Z main -                        https://docs.snyk.io/error-catalog#snyk-0005",
		"2026-06-10T13:10:38Z main - Exit Code:             2",
	}, "\n")

	report, err := Analyze(context.Background(), strings.NewReader(log), DefaultLogChecks())
	require.NoError(t, err)

	// Verbatim block preserved, including the detail the findings-only path dropped.
	assert.Contains(t, report.Result, "Authentication error (SNYK-0005)")
	assert.Contains(t, report.Result, "Description:")
	assert.Contains(t, report.Result, "https://docs.snyk.io/error-catalog#snyk-0005")
	assert.Contains(t, report.Result, "Exit Code:")

	// Structured signals are still extracted from the same block.
	var hasErrorCode, hasExit bool
	for _, f := range report.Findings {
		if f.Kind == KindErrorCode {
			hasErrorCode = true
			assert.Equal(t, "SNYK-0005", f.Code)
		}
		if f.Kind == KindExitCode {
			hasExit = true
		}
	}
	assert.True(t, hasErrorCode, "expected structured error-code finding")
	assert.True(t, hasExit, "expected structured exit-code finding")
}

func TestAnalyze_stampsSchemaVersion(t *testing.T) {
	report, err := Analyze(context.Background(),
		strings.NewReader("2026-06-10T13:10:38Z main - Exit Code: 0"), DefaultLogChecks())
	require.NoError(t, err)
	assert.Equal(t, SchemaVersion, report.SchemaVersion)
}

func TestAnalyze_resultStopsAtExitCode(t *testing.T) {
	// Trailing CI wrapper output (e.g. GitHub Actions post-job steps) after the
	// exit code must not leak into the result block.
	log := strings.Join([]string{
		"2026-06-26T13:58:20.0Z 2026-06-26T13:58:20Z main - ------------ Errors ------------",
		"2026-06-26T13:58:20.0Z 2026-06-26T13:58:20Z main - ERROR:                 Unspecified Error (SNYK-CLI-0000)",
		"2026-06-26T13:58:20.0Z 2026-06-26T13:58:20Z main - Exit Code:             2",
		"2026-06-26T13:58:42.8Z ##[error]Process completed with exit code 2.",
		"2026-06-26T13:58:42.9Z Post job cleanup.",
		"2026-06-26T13:58:43.0Z Cleaning up orphan processes",
	}, "\n")

	report, err := Analyze(context.Background(), strings.NewReader(log), DefaultLogChecks())
	require.NoError(t, err)

	assert.Contains(t, report.Result, "Exit Code:")
	assert.NotContains(t, report.Result, "Post job cleanup")
	assert.NotContains(t, report.Result, "Process completed")
	assert.NotContains(t, report.Result, "orphan processes")
}

func TestExtractSummary_cleansValues(t *testing.T) {
	header := []ParsedLine{
		{Number: 1, Message: "Authorization:         a6a2f94b***81310949  (type=pat)", HasCLIPrefix: true},
		{Number: 2, Message: "Features:              ", HasCLIPrefix: true},
		{Number: 3, Message: "  preview:             disabled", HasCLIPrefix: true},
		{Number: 4, Message: "  fips:                Not available", HasCLIPrefix: true},
	}

	summary := ExtractSummary(header)
	require.Len(t, summary.Fields, 2)

	// Column-alignment padding is collapsed.
	assert.Equal(t, "a6a2f94b***81310949 (type=pat)", summary.Fields[0].Value)

	// A parent field whose value is only indented sub-items must not start with
	// a stray newline.
	assert.Equal(t, "Features", summary.Fields[1].Key)
	assert.Equal(t, "preview: disabled\nfips: Not available", summary.Fields[1].Value)
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
