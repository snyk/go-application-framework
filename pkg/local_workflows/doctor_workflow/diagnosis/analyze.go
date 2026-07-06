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
				Producer: ProducerCLIResult,
				Kind:     KindExitCode,
				Severity: sev,
				Message:  "Exit code: " + codeStr,
				Subject:  fmt.Sprintf("L%d", ln.Number),
				Lines:    []int{ln.Number},
				Fields:   map[string]string{"exitCode": codeStr},
			})

		case strings.HasPrefix(msg, errorPrefix):
			code := extractSnykCode(msg)
			findings = append(findings, Finding{
				Producer: ProducerCLIResult,
				Kind:     KindErrorCode,
				Severity: SeverityError,
				Message:  cleanErrorMessage(msg, code),
				Subject:  fmt.Sprintf("L%d", ln.Number),
				Lines:    []int{ln.Number},
				Code:     code,
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

// cleanErrorMessage turns a raw "ERROR:" footer line into a concise message:
// drops the redundant "ERROR:" label (the Kind already conveys it), collapses
// the CLI's column padding, and removes a duplicated trailing code.
func cleanErrorMessage(msg, code string) string {
	text := normalizeSpace(strings.TrimPrefix(msg, errorPrefix))
	if code != "" {
		suffix := "(" + code + ")"
		text = strings.Replace(text, suffix+" "+suffix, suffix, 1)
	}
	return text
}
