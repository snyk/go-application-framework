package diagnosis

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

const (
	errorPrefix     = "ERROR:"
	errorsMarkerAlt = "------------ Errors ------------"
)

// snykCodeRe extracts a trailing error-catalog code, e.g. "(SNYK-CLI-0021)".
var snykCodeRe = regexp.MustCompile(`\(([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)\)`)

// Analyze orchestrates log parsing, check execution, and footer extraction
// to produce a DoctorReport.
func Analyze(ctx context.Context, r io.Reader, checks []LogCheck) (*DoctorReport, error) {
	_ = ctx // reserved for future LiveCheck cancellation

	lines, err := ParseLines(r)
	if err != nil {
		return nil, err
	}

	header, body, footer := SplitSections(lines)
	// Drop anything after the exit code (e.g. CI post-job steps appended to the
	// same stream).
	footer = truncateAtExitCode(footer)
	summary := ExtractSummary(header)

	var findings []Finding
	for _, check := range checks {
		findings = append(findings, check.Analyze(body)...)
	}

	findings = append(findings, parseResultFindings(footer)...)

	// Suppress findings that reflect normal CLI behavior (e.g. feature-flag 403s).
	findings = refineFindings(findings)

	return &DoctorReport{
		SchemaVersion: SchemaVersion,
		Summary:       summary,
		Findings:      findings,
		Result:        rawResult(footer),
	}, nil
}

// truncateAtExitCode returns the footer up to and including the exit-code line.
func truncateAtExitCode(footer []ParsedLine) []ParsedLine {
	for i, ln := range footer {
		if isExitCode(ln) {
			return footer[:i+1]
		}
	}
	return footer
}

// rawResult joins the footer into the verbatim result/errors block, preserving
// detail (Description, Links, Requests) that the findings don't capture.
func rawResult(footer []ParsedLine) string {
	if len(footer) == 0 {
		return ""
	}
	parts := make([]string, len(footer))
	for i, ln := range footer {
		parts[i] = strings.TrimRight(ln.Message, " \t")
	}
	return strings.Join(parts, "\n")
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
			codeStr := strings.TrimSpace(strings.TrimPrefix(msg, exitCodePrefix))
			sev := SeverityError
			if code, err := strconv.Atoi(codeStr); err == nil && code == 0 {
				sev = SeverityInfo
			}
			findings = append(findings, Finding{
				Source:   SourceCLIResult,
				Kind:     KindExitCode,
				Severity: sev,
				Message:  ln.Message,
				Subject:  fmt.Sprintf("L%d", ln.Number),
				Lines:    []int{ln.Number},
				Fields:   map[string]string{"exitCode": codeStr},
			})

		case strings.HasPrefix(msg, errorPrefix):
			findings = append(findings, Finding{
				Source:   SourceCLIResult,
				Kind:     KindErrorCode,
				Severity: SeverityError,
				Message:  ln.Message,
				Subject:  fmt.Sprintf("L%d", ln.Number),
				Lines:    []int{ln.Number},
				Code:     extractSnykCode(msg),
			})

		default:
			continue
		}
	}
	return findings
}

// extractSnykCode returns the error-catalog code embedded in a message, e.g.
// "SNYK-0005" from "ERROR: Authentication error (SNYK-0005)", or "" if none.
func extractSnykCode(msg string) string {
	if m := snykCodeRe.FindStringSubmatch(msg); m != nil {
		return m[1]
	}
	return ""
}
