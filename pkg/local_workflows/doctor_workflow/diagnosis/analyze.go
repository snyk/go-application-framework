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

// httpURLRe matches a URL inside an error block's "Links:" section.
var httpURLRe = regexp.MustCompile(`https?://\S+`)

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

	if len(findings) == 0 {
		findings = append(findings, Finding{
			Producer: ProducerLogAnalysis,
			Title:    "Nothing found",
			Message:  "We didn't discover known issues from the given debug logs",
			Severity: SeverityWarning,
		})
	}

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
	for i, ln := range footer {
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
				Subject:  fmt.Sprintf("%d", ln.Number),
				Lines:    []int{ln.Number},
				Fields:   map[string]string{"exitCode": codeStr},
			})

		case strings.HasPrefix(msg, errorPrefix):
			code := extractSnykCode(msg)
			title := cleanErrorMessage(msg, code)
			// The indented block after the ERROR line holds the real cause
			// (Description/Instance) and doc links; lift them into the finding.
			cause, links := parseErrorDetail(footer, i+1)
			message := cause
			if message == "" {
				message = title
			}
			findings = append(findings, Finding{
				Producer:    ProducerCLIResult,
				Kind:        KindErrorCode,
				Severity:    SeverityError,
				Title:       title,
				Message:     message,
				Subject:     fmt.Sprintf("%d", ln.Number),
				Lines:       []int{ln.Number},
				Code:        code,
				Remediation: links,
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

// parseErrorDetail reads the indented block that follows an "ERROR:" line and
// returns the human cause (Description/Instance text, joined) plus any doc
// links. It stops at the next top-level line (e.g. "Exit Code:" or another
// "ERROR:"). Section labels ("Links:", "Instance 1:", "Description:") are
// dropped; only their values are kept.
func parseErrorDetail(footer []ParsedLine, start int) (cause string, links []string) {
	var parts []string
	for i := start; i < len(footer); i++ {
		raw := footer[i].Message
		trimmed := strings.TrimSpace(raw)

		if trimmed != "" && !startsWithSpace(raw) {
			break // next top-level line ends this error's block
		}
		switch {
		case trimmed == "":
			continue
		case httpURLRe.MatchString(trimmed):
			links = append(links, httpURLRe.FindString(trimmed))
		case strings.HasSuffix(trimmed, ":"):
			continue // section label, e.g. "Instance 1:"
		default:
			parts = append(parts, normalizeSpace(trimmed))
		}
	}
	return strings.Join(parts, " "), links
}

func startsWithSpace(s string) bool {
	return len(s) > 0 && (s[0] == ' ' || s[0] == '\t')
}
