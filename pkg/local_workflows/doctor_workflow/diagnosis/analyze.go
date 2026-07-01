package diagnosis

import (
	"context"
	"io"
	"strings"
)

const (
	errorPrefix     = "ERROR:"
	errorsMarkerAlt = "------------ Errors ------------"
)

// Analyze orchestrates log parsing, check execution, and footer extraction
// to produce a DoctorReport.
func Analyze(ctx context.Context, r io.Reader, checks []LogCheck) (*DoctorReport, error) {
	_ = ctx // reserved for future LiveCheck cancellation

	lines, err := ParseLines(r)
	if err != nil {
		return nil, err
	}

	header, body, footer := SplitSections(lines)
	summary := ExtractSummary(header)

	var findings []Finding
	for _, check := range checks {
		findings = append(findings, check.Analyze(body)...)
	}

	findings = append(findings, parseResultFindings(footer)...)

	return &DoctorReport{
		Summary:  summary,
		Findings: findings,
	}, nil
}

// parseResultFindings extracts findings from the footer/result section.
func parseResultFindings(footer []ParsedLine) []Finding {
	var findings []Finding
	for _, ln := range footer {
		msg := strings.TrimSpace(ln.Message)

		switch {
		case msg == "" || msg == errorsMarkerAlt:
			continue

		case strings.HasPrefix(msg, exitCodePrefix):
			code := strings.TrimSpace(strings.TrimPrefix(msg, exitCodePrefix))
			sev := SeverityInfo
			if code != "0" {
				sev = SeverityError
			}
			findings = append(findings, Finding{
				Source:   SourceCLIResult,
				Line:     ln.Number,
				Kind:     KindExitCode,
				Severity: sev,
				Message:  ln.Message,
			})

		case strings.HasPrefix(msg, errorPrefix):
			findings = append(findings, Finding{
				Source:   SourceCLIResult,
				Line:     ln.Number,
				Kind:     KindErrorCode,
				Severity: SeverityError,
				Message:  ln.Message,
			})

		default:
			continue
		}
	}
	return findings
}
