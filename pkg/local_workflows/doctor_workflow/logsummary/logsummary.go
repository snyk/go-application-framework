package logsummary

import "strings"

const maxHighlights = 200

type EventKind string

const (
	EventHTTPError EventKind = "http-error"
	EventError     EventKind = "error"
)

type Highlight struct {
	Line    int
	Kind    EventKind
	Message string
}

type Summary struct {
	CLIVersion   string
	FormatSpecID string
	Header       string
	Footer       string
	Highlights   []Highlight
	Truncated    bool
}

func Summarize(log string) Summary {
	rawLines := strings.Split(log, "\n")
	spec := detectFormat(rawLines)
	tokens := tokenize(spec.Lexer, rawLines)
	landmarks := findLandmarks(tokens, spec.LandmarkRules)
	sections := splitByLandmarks(tokens, landmarks, spec.LandmarkRules)

	headerTokens, bodyRemainder := extractHeaderFromRegion(sections[SectionHeader])

	var bodyTokens []TokenizedLine
	bodyTokens = append(bodyTokens, sections[SectionPreamble]...)
	bodyTokens = append(bodyTokens, bodyRemainder...)
	bodyTokens = append(bodyTokens, sections[SectionBody]...)

	highlights, truncated := collectHighlights(bodyTokens)

	cliVer, _ := extractCLIVersion(rawLines)
	return Summary{
		CLIVersion:   cliVer.Raw,
		FormatSpecID: spec.ID,
		Header:       joinMessages(headerTokens),
		Footer:       joinFooter(sections[SectionSummary], sections[SectionResult]),
		Highlights:   highlights,
		Truncated:    truncated,
	}
}

func collectHighlights(tokens []TokenizedLine) ([]Highlight, bool) {
	var highlights []Highlight
	seen := make(map[string]struct{})
	for _, tok := range tokens {
		kind := tokenToEventKind(tok.Token)
		if kind == "" {
			continue
		}
		if _, dup := seen[tok.Message]; dup {
			continue
		}
		seen[tok.Message] = struct{}{}
		highlights = append(highlights, Highlight{
			Line:    tok.Number,
			Kind:    kind,
			Message: tok.Message,
		})
		if len(highlights) == maxHighlights {
			return highlights, true
		}
	}
	return highlights, false
}

func tokenToEventKind(t Token) EventKind {
	switch t {
	case TokenHTTPError:
		return EventHTTPError
	case TokenCLIError, TokenFailedLine:
		return EventError
	}
	return ""
}

func joinMessages(tokens []TokenizedLine) string {
	if len(tokens) == 0 {
		return ""
	}
	parts := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		parts = append(parts, tok.Message)
	}
	return strings.Join(parts, "\n")
}

func joinFooter(summaryTokens, resultTokens []TokenizedLine) string {
	var footerTokens []TokenizedLine

	// If we have a result section (errors marker or exit code), skip the summary
	// section content and use the result directly.
	if len(resultTokens) > 0 {
		footerTokens = resultTokens
	} else if len(summaryTokens) > 0 {
		// Summary block exists but no errors/exit code after it
		footerTokens = summaryTokens
	}

	result := joinMessages(footerTokens)
	return trimTrailingBlanks(result)
}

func trimTrailingBlanks(s string) string {
	for strings.HasSuffix(s, "\n") || strings.HasSuffix(s, "\n ") {
		s = strings.TrimRight(s, " \n")
	}
	return s
}
