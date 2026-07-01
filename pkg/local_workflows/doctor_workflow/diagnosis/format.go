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

	// Environment section
	write("\n\nEnvironment\n\n")
	if report.Summary.Raw == "" {
		write("  (not found in the provided log)\n")
	} else {
		for line := range strings.SplitSeq(report.Summary.Raw, "\n") {
			write("  %s\n", strings.TrimRight(line, " "))
		}
	}

	// Notable Events — log-analysis findings
	write("\n\nNotable Events\n\n")
	logFindings := filterBySource(report.Findings, SourceLogAnalysis)
	if len(logFindings) == 0 {
		write("  No failing requests or CLI error entries found in the log body.\n")
	} else {
		for _, f := range logFindings {
			write("  L%d [%s] %s\n", f.Line, f.Kind, f.Message)
		}
	}

	// Result section — cli-result findings
	write("\n\nResult\n\n")
	resultFindings := filterBySource(report.Findings, SourceCLIResult)
	if len(resultFindings) == 0 {
		write("  (not found in the provided log)\n")
	} else {
		for _, f := range resultFindings {
			write("  %s\n", strings.TrimRight(f.Message, " "))
		}
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
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
