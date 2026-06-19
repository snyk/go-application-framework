package logsummary

import (
	"regexp"
	"strings"
)

type EventKind string

const (
	EventHTTPError EventKind = "http-error"
	EventError     EventKind = "error"
)

const (
	maxHighlights  = 200
	summaryMarker  = "------------ Summary ------------"
	errorsMarker   = "------------ Errors ------------"
	versionPrefix  = "Version:"
	exitCodePrefix = "Exit Code:"
	cliErrorPrefix = "< error:"
	failedPrefix   = "Failed "
)

var (
	// cliPrefixRe matches the Snyk CLI debug prefix, e.g. "2026-06-10T13:10:38Z main - ".
	cliPrefixRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\S+ \S+ - ?`)
	// tableRowRe identifies rows in the CLI environment table so unknown fields
	// added by future CLI versions still stay in the Environment section.
	tableRowRe = regexp.MustCompile(`^[A-Za-z][\w .-]*:`)
	// responseRe matches an HTTP response line with a 4xx/5xx status.
	responseRe = regexp.MustCompile(`^< response \[0x[0-9a-fA-F]+\]:\s*[45]\d{2}\b`)
)

type Highlight struct {
	Line    int
	Kind    EventKind
	Message string
}

type Summary struct {
	Header     string
	Footer     string
	Highlights []Highlight
	Truncated  bool
}

type logLine struct {
	lineNumber   int
	message      string
	hasCLIPrefix bool
}

func Summarize(log string) Summary {
	lines := normalizeLines(log)
	body, result := splitSections(lines)
	header := extractHeader(body)
	highlights, truncated := collectHighlights(body)

	return Summary{
		Header:     joinMessages(header),
		Footer:     joinMessages(result),
		Highlights: highlights,
		Truncated:  truncated,
	}
}

func normalizeLines(log string) []logLine {
	rawLines := strings.Split(log, "\n")
	lines := make([]logLine, 0, len(rawLines))
	for i, raw := range rawLines {
		message, hasCLIPrefix := stripPrefix(raw)
		lines = append(lines, logLine{
			lineNumber:   i + 1,
			message:      message,
			hasCLIPrefix: hasCLIPrefix,
		})
	}
	return lines
}

func splitSections(lines []logLine) (body, result []logLine) {
	if summaryIndex := indexOf(lines, 0, isSummaryMarker); summaryIndex >= 0 {
		resultStart := resultStartAfterSummary(lines, summaryIndex+1)
		if resultStart < 0 {
			return lines[:summaryIndex], nil
		}
		return lines[:summaryIndex], trimTrailingBlankLines(lines[resultStart:])
	}

	if exitIndex := indexOf(lines, 0, isExitCode); exitIndex >= 0 {
		return lines[:exitIndex], trimTrailingBlankLines(lines[exitIndex:])
	}

	return lines, nil
}

func resultStartAfterSummary(lines []logLine, start int) int {
	if errorsIndex := indexOf(lines, start, isErrorsMarker); errorsIndex >= 0 {
		return errorsIndex
	}
	return indexOf(lines, start, isExitCode)
}

func extractHeader(body []logLine) []logLine {
	start := indexOf(body, 0, isHeaderStart)
	if start < 0 {
		return nil
	}

	end := start
	for i := start + 1; i < len(body); i++ {
		ln := body[i]
		if !ln.hasCLIPrefix || classifyBodyLine(ln) != "" || !isTableRow(ln.message) {
			break
		}
		end = i
	}

	return body[start : end+1]
}

func collectHighlights(body []logLine) ([]Highlight, bool) {
	highlights := make([]Highlight, 0)
	seen := make(map[string]struct{})
	for _, line := range body {
		kind := classifyBodyLine(line)
		if kind == "" {
			continue
		}

		if _, dup := seen[line.message]; dup {
			continue
		}
		seen[line.message] = struct{}{}
		highlights = append(highlights, Highlight{
			Line:    line.lineNumber,
			Kind:    kind,
			Message: line.message,
		})
		if len(highlights) == maxHighlights {
			return highlights, true
		}
	}
	return highlights, false
}

// classifyBodyLine returns the notable event kind for a body line, or "" when
// the line is not notable. Only prefixed CLI lines are considered.
func classifyBodyLine(line logLine) EventKind {
	if !line.hasCLIPrefix {
		return ""
	}
	switch {
	case responseRe.MatchString(line.message):
		return EventHTTPError
	case strings.HasPrefix(line.message, cliErrorPrefix), strings.HasPrefix(line.message, failedPrefix):
		return EventError
	}
	return ""
}

func indexOf(lines []logLine, start int, match func(logLine) bool) int {
	for i := start; i < len(lines); i++ {
		if match(lines[i]) {
			return i
		}
	}
	return -1
}

func joinMessages(lines []logLine) string {
	parts := make([]string, 0, len(lines))
	for _, ln := range lines {
		parts = append(parts, ln.message)
	}
	return strings.Join(parts, "\n")
}

func trimTrailingBlankLines(lines []logLine) []logLine {
	end := len(lines)
	for end > 0 && strings.TrimSpace(lines[end-1].message) == "" {
		end--
	}
	return lines[:end]
}

func isHeaderStart(ln logLine) bool {
	return ln.hasCLIPrefix && strings.HasPrefix(ln.message, versionPrefix)
}

func isSummaryMarker(ln logLine) bool {
	return strings.TrimSpace(ln.message) == summaryMarker
}

func isErrorsMarker(ln logLine) bool {
	return strings.TrimSpace(ln.message) == errorsMarker
}

func isExitCode(ln logLine) bool {
	return strings.HasPrefix(ln.message, exitCodePrefix)
}

func stripPrefix(line string) (message string, hasCLIPrefix bool) {
	if loc := cliPrefixRe.FindStringIndex(line); loc != nil {
		return line[loc[1]:], true
	}
	return line, false
}

func isTableRow(msg string) bool {
	return msg != "" && (msg[0] == ' ' || msg[0] == '\t' || tableRowRe.MatchString(msg))
}
