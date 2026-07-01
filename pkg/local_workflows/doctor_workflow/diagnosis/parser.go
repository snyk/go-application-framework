package diagnosis

import (
	"bufio"
	"io"
	"regexp"
	"strings"
)

const (
	summaryMarker  = "------------ Summary ------------"
	errorsMarker   = "------------ Errors ------------"
	versionPrefix  = "Version:"
	exitCodePrefix = "Exit Code:"
)

var (
	// cliPrefixRe matches the Snyk CLI debug prefix, e.g. "2026-06-10T13:10:38Z main - ".
	cliPrefixRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\S+ \S+ - ?`)
	// tableRowRe identifies rows in the CLI environment table so unknown fields
	// added by future CLI versions still stay in the Environment section.
	tableRowRe = regexp.MustCompile(`^[A-Za-z][\w .-]*:`)
)

// ParsedLine is a single line from a debug log after prefix normalization.
type ParsedLine struct {
	Number       int
	Message      string
	HasCLIPrefix bool
}

// ParseLines reads lines from r and normalizes each by stripping the CLI debug prefix.
func ParseLines(r io.Reader) ([]ParsedLine, error) {
	var lines []ParsedLine
	scanner := bufio.NewScanner(r)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		message, hasCLIPrefix := stripPrefix(raw)
		lines = append(lines, ParsedLine{
			Number:       lineNum,
			Message:      message,
			HasCLIPrefix: hasCLIPrefix,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

// SplitSections divides parsed lines into header (environment), body (log events),
// and footer (result/exit code) sections.
func SplitSections(lines []ParsedLine) (header, body, footer []ParsedLine) {
	// Find the summary marker to split body from footer.
	summaryIdx := indexOfLine(lines, 0, isSummaryMarker)

	var bodyLines, footerLines []ParsedLine
	if summaryIdx >= 0 {
		bodyLines = lines[:summaryIdx]
		resultStart := resultStartAfterSummary(lines, summaryIdx+1)
		if resultStart >= 0 {
			footerLines = trimTrailingBlankLines(lines[resultStart:])
		}
	} else if exitIdx := indexOfLine(lines, 0, isExitCode); exitIdx >= 0 {
		bodyLines = lines[:exitIdx]
		footerLines = trimTrailingBlankLines(lines[exitIdx:])
	} else {
		bodyLines = lines
	}

	headerLines := extractHeader(bodyLines)
	return headerLines, bodyLines, footerLines
}

// ExtractSummary parses header lines into a Summary with structured Fields
// and a Raw copy of the original text.
func ExtractSummary(header []ParsedLine) Summary {
	if len(header) == 0 {
		return Summary{}
	}

	var fields []KeyValue
	var rawParts []string

	for _, ln := range header {
		rawParts = append(rawParts, ln.Message)

		// Continuation line (indented): append to previous field's value.
		if len(ln.Message) > 0 && (ln.Message[0] == ' ' || ln.Message[0] == '\t') {
			if len(fields) > 0 {
				fields[len(fields)-1].Value += "\n" + strings.TrimSpace(ln.Message)
			}
			continue
		}

		// Key:Value line
		if idx := strings.Index(ln.Message, ":"); idx >= 0 {
			key := strings.TrimSpace(ln.Message[:idx])
			value := strings.TrimSpace(ln.Message[idx+1:])
			fields = append(fields, KeyValue{Key: key, Value: value})
		}
	}

	return Summary{
		Fields: fields,
		Raw:    strings.Join(rawParts, "\n"),
	}
}

func extractHeader(body []ParsedLine) []ParsedLine {
	start := indexOfLine(body, 0, isHeaderStart)
	if start < 0 {
		return nil
	}

	end := start
	for i := start + 1; i < len(body); i++ {
		ln := body[i]
		if !ln.HasCLIPrefix || classifyBodyLine(ln) != "" || !isTableRow(ln.Message) {
			break
		}
		end = i
	}

	return body[start : end+1]
}

func resultStartAfterSummary(lines []ParsedLine, start int) int {
	if errorsIdx := indexOfLine(lines, start, isErrorsMarker); errorsIdx >= 0 {
		return errorsIdx
	}
	return indexOfLine(lines, start, isExitCode)
}

func indexOfLine(lines []ParsedLine, start int, match func(ParsedLine) bool) int {
	for i := start; i < len(lines); i++ {
		if match(lines[i]) {
			return i
		}
	}
	return -1
}

func trimTrailingBlankLines(lines []ParsedLine) []ParsedLine {
	end := len(lines)
	for end > 0 && strings.TrimSpace(lines[end-1].Message) == "" {
		end--
	}
	return lines[:end]
}

func isHeaderStart(ln ParsedLine) bool {
	return ln.HasCLIPrefix && strings.HasPrefix(ln.Message, versionPrefix)
}

func isSummaryMarker(ln ParsedLine) bool {
	return strings.TrimSpace(ln.Message) == summaryMarker
}

func isErrorsMarker(ln ParsedLine) bool {
	return strings.TrimSpace(ln.Message) == errorsMarker
}

func isExitCode(ln ParsedLine) bool {
	return strings.HasPrefix(ln.Message, exitCodePrefix)
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
