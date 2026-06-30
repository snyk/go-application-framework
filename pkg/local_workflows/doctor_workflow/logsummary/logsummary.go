package logsummary

import "strings"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// EventKind categorizes a notable log event.
type EventKind string

const (
	EventHTTPError EventKind = "http-error"
	EventError     EventKind = "error"
)

const maxHighlights = 200

// Highlight is a notable event extracted from the log body.
type Highlight struct {
	Line    int
	Kind    EventKind
	Message string
}

// Summary is the result of parsing a CLI debug log.
type Summary struct {
	CLIVersion   string
	FormatSpecID string
	Header       string
	Footer       string
	Highlights   []Highlight
	Truncated    bool
}

// ---------------------------------------------------------------------------
// Summarize: 3-phase pipeline entry point
// ---------------------------------------------------------------------------

// Summarize parses a CLI debug log and returns a structured summary.
//
// Phase 1: Tokenize each line using the detected format spec's lexer.
// Phase 2: Find structural landmarks, carve token stream into sections.
// Phase 3: Process each section independently (header, highlights, footer).
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

// ---------------------------------------------------------------------------
// Internal: highlight collection (Phase 3)
// ---------------------------------------------------------------------------

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
	case TokenPlain, TokenBlank, TokenVersionLine, TokenTableRow,
		TokenSummaryMarker, TokenErrorsMarker, TokenExitCode:
		return ""
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// Internal: message joining and footer assembly
// ---------------------------------------------------------------------------

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
	if len(resultTokens) > 0 {
		footerTokens = resultTokens
	} else if len(summaryTokens) > 0 {
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
