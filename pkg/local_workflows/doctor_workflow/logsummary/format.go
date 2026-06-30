package logsummary

import (
	"fmt"
	"strings"
)

// Format renders the Summary as a human-readable diagnostic report.
func (summary Summary) Format() string {
	var sb strings.Builder

	sb.WriteString("Snyk Doctor Diagnostic Report\n")

	if summary.CLIVersion != "" {
		fmt.Fprintf(&sb, "CLI Version: %s (parsed with format spec %q)\n", summary.CLIVersion, summary.FormatSpecID)
	}

	writeSection(&sb, "Environment", summary.Header)

	sb.WriteString("\n\nNotable Events\n\n")
	if len(summary.Highlights) == 0 {
		sb.WriteString("  No failing requests or CLI error entries found in the log body.\n")
	} else {
		for _, h := range summary.Highlights {
			fmt.Fprintf(&sb, "  L%d [%s] %s\n", h.Line, h.Kind, h.Message)
		}
		if summary.Truncated {
			fmt.Fprintf(&sb, "  (showing first %d notable events; remaining log not scanned)\n", maxHighlights)
		}
	}

	writeSection(&sb, "Result", summary.Footer)

	return sb.String()
}

func writeSection(sb *strings.Builder, title, content string) {
	fmt.Fprintf(sb, "\n\n%s\n\n", title)
	if content == "" {
		sb.WriteString("  (not found in the provided log)\n")
		return
	}
	for _, line := range strings.Split(content, "\n") {
		fmt.Fprintf(sb, "  %s\n", strings.TrimRight(line, " "))
	}
}
