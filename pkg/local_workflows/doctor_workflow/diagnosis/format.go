package diagnosis

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// FormatText writes a human-readable diagnostic report to w.
func FormatText(w io.Writer, report *DoctorReport) error {
	var errs []error
	write := func(format string, args ...interface{}) {
		if _, err := fmt.Fprintf(w, format, args...); err != nil {
			errs = append(errs, err)
		}
	}

	write("Snyk Doctor Diagnostic Report\n")

	// Environment and Result render verbatim; findings render per source.
	writeRawSection(write, "Environment", report.Summary.Raw)
	writeFindingsSection(write, "Notable Events", filterBySource(report.Findings, SourceLogAnalysis),
		"No failing requests or CLI error entries found in the log body.")
	writeRawSection(write, "Result", report.Result)

	// Additional producers (connectivity, auth, ...) get a section each, with no
	// per-producer formatter code.
	for _, source := range extraSources(report.Findings) {
		writeFindingsSection(write, sourceTitle(source), filterBySource(report.Findings, source), "")
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// writeRawSection prints a verbatim text block (environment header or result
// footer), preserving the CLI's own layout.
func writeRawSection(write func(string, ...interface{}), title, raw string) {
	write("\n\n%s\n\n", title)
	if raw == "" {
		write("  (not found in the provided log)\n")
		return
	}
	for line := range strings.SplitSeq(raw, "\n") {
		write("  %s\n", strings.TrimRight(line, " "))
	}
}

// writeFindingsSection renders a section of findings uniformly from the generic
// Finding fields, without knowing which producer emitted them.
func writeFindingsSection(write func(string, ...interface{}), title string, findings []Finding, emptyMessage string) {
	write("\n\n%s\n\n", title)
	if len(findings) == 0 {
		if emptyMessage != "" {
			write("  %s\n", emptyMessage)
		}
		return
	}
	for _, f := range findings {
		writeFinding(write, f)
	}
}

func writeFinding(write func(string, ...interface{}), f Finding) {
	subject := ""
	if f.Subject != "" {
		subject = f.Subject + " "
	}
	code := ""
	if f.Code != "" {
		code = " (" + f.Code + ")"
	}
	write("  %s[%s] %s%s\n", subject, f.Kind, strings.TrimRight(f.Message, " "), code)
	for _, step := range f.Remediation {
		write("      → %s\n", step)
	}
	for _, detail := range f.Details {
		write("      %s\n", detail)
	}
}

// extraSources returns, in first-seen order, the finding sources beyond the two
// core log sections, so new producers surface without formatter changes.
func extraSources(findings []Finding) []string {
	seen := map[string]bool{SourceLogAnalysis: true, SourceCLIResult: true}
	var sources []string
	for _, f := range findings {
		if !seen[f.Source] {
			seen[f.Source] = true
			sources = append(sources, f.Source)
		}
	}
	return sources
}

// sourceTitle maps a source to a friendly section header, falling back to the
// raw source label for unknown producers.
func sourceTitle(source string) string {
	switch source {
	case SourceConnectivity:
		return "Connectivity"
	case SourceAuth:
		return "Authentication"
	default:
		return source
	}
}

// FormatJSON writes the report as JSON to w.
func FormatJSON(w io.Writer, report *DoctorReport) error {
	return json.NewEncoder(w).Encode(report)
}

func filterBySource(findings []Finding, source string) []Finding {
	var result []Finding
	for _, f := range findings {
		if f.Source == source {
			result = append(result, f)
		}
	}
	return result
}
