package diagnosis

import (
	"fmt"
	"strings"
)

const (
	maxHighlights  = 200
	cliErrorPrefix = "< error:"
	failedPrefix   = "Failed "
)

// ErrorEventCheck detects CLI error lines in the log body. HTTP request/response
// errors are handled by CorrelationCheck (which produces richer, correlated
// findings), so this check deliberately does not classify response lines.
type ErrorEventCheck struct{}

func (c *ErrorEventCheck) Name() string { return "error-events" }

func (c *ErrorEventCheck) Analyze(body []ParsedLine) []Finding {
	findings := make([]Finding, 0)
	seen := make(map[string]struct{})

	for _, line := range body {
		kind := classifyBodyLine(line)
		if kind == "" {
			continue
		}

		if _, dup := seen[line.Message]; dup {
			continue
		}
		seen[line.Message] = struct{}{}

		findings = append(findings, Finding{
			Producer: ProducerLogAnalysis,
			Kind:     kind,
			Severity: SeverityError,
			Message:  line.Message,
			Subject:  fmt.Sprintf("%d", line.Number),
			Lines:    []int{line.Number},
		})

		if len(findings) == maxHighlights {
			break
		}
	}
	return findings
}

// classifyBodyLine returns the finding kind for a body line, or "" when the line
// is not a CLI error. Only prefixed CLI lines are considered.
func classifyBodyLine(line ParsedLine) Kind {
	if !line.HasCLIPrefix {
		return ""
	}
	switch {
	case strings.HasPrefix(line.Message, cliErrorPrefix), strings.HasPrefix(line.Message, failedPrefix):
		return KindCLIError
	}
	return ""
}
