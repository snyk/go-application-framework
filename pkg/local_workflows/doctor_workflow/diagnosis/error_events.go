package diagnosis

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	maxHighlights  = 200
	cliErrorPrefix = "< error:"
	failedPrefix   = "Failed "
)

// responseRe matches an HTTP response line with a 4xx/5xx status.
var responseRe = regexp.MustCompile(`^< response \[0x[0-9a-fA-F]+\]:\s*[45]\d{2}\b`)

// ErrorEventCheck detects HTTP errors and CLI error lines in log body.
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
			Source:   SourceLogAnalysis,
			Kind:     kind,
			Severity: SeverityError,
			Message:  line.Message,
			Subject:  fmt.Sprintf("L%d", line.Number),
		})

		if len(findings) == maxHighlights {
			break
		}
	}
	return findings
}

// classifyBodyLine returns the finding kind for a body line, or "" when
// the line is not notable. Only prefixed CLI lines are considered.
func classifyBodyLine(line ParsedLine) string {
	if !line.HasCLIPrefix {
		return ""
	}
	switch {
	case responseRe.MatchString(line.Message):
		return KindHTTPError
	case strings.HasPrefix(line.Message, cliErrorPrefix), strings.HasPrefix(line.Message, failedPrefix):
		return KindCLIError
	}
	return ""
}
