// Package logscan extracts diagnostic signals from Snyk CLI debug logs:
// the log header and footer are lifted verbatim as whole blocks (no
// field-level parsing, the format is owned by the CLI and drifts), and the
// body is scanned for notable events (failing HTTP requests, error/warn
// entries) so the noisy lines of normally-succeeding operations stay out of
// the consolidated report.
package logscan

import (
	"regexp"
	"strconv"
	"strings"
)

type EventKind string

const (
	EventHTTPError EventKind = "http-error"
	EventError     EventKind = "error"
	EventWarn      EventKind = "warn"
)

// maxEvents caps the extracted events; retry storms can produce huge logs
// and the report must stay small enough to hand to an LLM.
const maxEvents = 200

type NotableEvent struct {
	Line int
	Kind EventKind
	Text string
	// Message is Text without the timestamp prefix and with volatile tokens
	// (pointer addresses) normalized, so identical events from retries can
	// be grouped for presentation.
	Message string
}

type ScanResult struct {
	Header        string
	Footer        string
	NotableEvents []NotableEvent
}

var (
	// "2026-06-10T13:10:38Z main - <message>"; empty messages end at the
	// dash with no trailing space
	linePrefixRe = regexp.MustCompile(`^\S+ \S+ - ?(.*)$`)
	// "< response [0x2b3cd0a17cc0]: 401 Unauthorized"
	responseStatusRe = regexp.MustCompile(`< response \[0x[0-9a-fA-F]+\]: (\d{3})\b`)
	// header block lines are "Key:  value" or indented continuations
	headerKeyRe = regexp.MustCompile(`^[A-Z][A-Za-z ]*:`)
	// request/response correlation pointers, volatile across retries
	pointerRe = regexp.MustCompile(`\[0x[0-9a-fA-F]+\]`)
)

// StripLinePrefixes removes the "<timestamp> <scope> - " prefix from every
// line of a lifted block, for presentation: the block content stays verbatim
// (no field parsing), only the per-line log envelope is dropped.
func StripLinePrefixes(block string) string {
	lines := strings.Split(block, "\n")
	for i, line := range lines {
		lines[i] = messageOf(line)
	}
	return strings.Join(lines, "\n")
}

func Scan(log string) ScanResult {
	lines := strings.Split(log, "\n")
	messages := make([]string, len(lines))
	for i, line := range lines {
		messages[i] = messageOf(line)
	}

	headerStart, headerEnd := headerBlock(lines, messages, firstVersionLine(messages))
	footerStart := lastVersionLine(messages)
	footerEnd := -1
	if footerStart >= 0 && footerStart != headerStart {
		footerEnd = len(lines) - 1
	} else {
		footerStart = -1
	}

	result := ScanResult{
		Header: joinBlock(lines, headerStart, headerEnd),
		Footer: joinBlock(lines, footerStart, footerEnd),
	}

	for i, line := range lines {
		if within(i, headerStart, headerEnd) || within(i, footerStart, footerEnd) {
			continue
		}
		if kind, ok := classify(messages[i]); ok {
			result.NotableEvents = append(result.NotableEvents, NotableEvent{
				Line:    i + 1,
				Kind:    kind,
				Text:    line,
				Message: pointerRe.ReplaceAllString(messages[i], "[0x*]"),
			})
			if len(result.NotableEvents) >= maxEvents {
				break
			}
		}
	}
	return result
}

// messageOf strips the "<timestamp> <scope> - " prefix; lines without the
// prefix (e.g. the multi-line sensitive-data banner) are returned as-is.
func messageOf(line string) string {
	if m := linePrefixRe.FindStringSubmatch(line); m != nil {
		return m[1]
	}
	return line
}

func firstVersionLine(messages []string) int {
	for i, msg := range messages {
		if strings.HasPrefix(msg, "Version:") {
			return i
		}
	}
	return -1
}

func lastVersionLine(messages []string) int {
	for i := len(messages) - 1; i >= 0; i-- {
		if strings.HasPrefix(messages[i], "Version:") {
			return i
		}
	}
	return -1
}

// headerBlock extends from the Version: line through consecutive "Key: value"
// lines and their indented continuations (e.g. the Features:/Checks: items).
func headerBlock(lines, messages []string, start int) (int, int) {
	if start < 0 {
		return -1, -1
	}
	end := start
	for i := start + 1; i < len(lines); i++ {
		msg := messages[i]
		if headerKeyRe.MatchString(msg) || strings.HasPrefix(msg, " ") || strings.HasPrefix(msg, "\t") {
			end = i
			continue
		}
		break
	}
	return start, end
}

func joinBlock(lines []string, start, end int) string {
	if start < 0 || end < start {
		return ""
	}
	return strings.Join(lines[start:end+1], "\n")
}

func within(i, start, end int) bool {
	return start >= 0 && i >= start && i <= end
}

func classify(msg string) (EventKind, bool) {
	if m := responseStatusRe.FindStringSubmatch(msg); m != nil {
		if code, err := strconv.Atoi(m[1]); err == nil && code >= 400 {
			return EventHTTPError, true
		}
		return "", false
	}
	if strings.Contains(msg, "< error:") || strings.HasPrefix(msg, "Failed ") || strings.Contains(msg, "ERROR") {
		return EventError, true
	}
	// the standard sensitive-data banner contains "WARNING" but is part of
	// every debug log, not a diagnostic signal
	if strings.Contains(msg, "WARN") && !strings.Contains(msg, "Potentially Sensitive Information") {
		return EventWarn, true
	}
	return "", false
}
