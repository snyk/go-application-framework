package logsummary

import (
	"strings"

	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/logparse"
)

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
// Constructors
// ---------------------------------------------------------------------------

// NewHighlight builds a Highlight.
func NewHighlight(line int, kind EventKind, message string) Highlight {
	return Highlight{Line: line, Kind: kind, Message: message}
}

// NewSummary builds a Summary.
func NewSummary(cliVersion, formatSpecID, header, footer string, highlights []Highlight, truncated bool) Summary {
	return Summary{
		CLIVersion:   cliVersion,
		FormatSpecID: formatSpecID,
		Header:       header,
		Footer:       footer,
		Highlights:   highlights,
		Truncated:    truncated,
	}
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

	detector := newDetector()
	spec := detector.Detect(rawLines)

	tokens := logparse.Tokenize(spec.Lexer, rawLines)
	landmarks := logparse.FindLandmarks(tokens, spec.LandmarkRules)
	sections := logparse.SplitByLandmarks(tokens, landmarks, spec.LandmarkRules)

	headerTokens, bodyRemainder := logparse.ExtractHeaderFromRegion(sections[logparse.SectionHeader])

	var bodyTokens []logparse.TokenizedLine
	bodyTokens = append(bodyTokens, sections[logparse.SectionPreamble]...)
	bodyTokens = append(bodyTokens, bodyRemainder...)
	bodyTokens = append(bodyTokens, sections[logparse.SectionBody]...)

	highlights, truncated := collectHighlights(bodyTokens)

	cliVer, _ := detector.ExtractCLIVersion(rawLines)
	return NewSummary(
		cliVer.Raw,
		spec.ID,
		joinMessages(headerTokens),
		joinFooter(sections[logparse.SectionSummary], sections[logparse.SectionResult]),
		highlights,
		truncated,
	)
}

// ---------------------------------------------------------------------------
// Internal: highlight collection (Phase 3)
// ---------------------------------------------------------------------------

func collectHighlights(tokens []logparse.TokenizedLine) ([]Highlight, bool) {
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
		highlights = append(highlights, NewHighlight(tok.Number, kind, tok.Message))
		if len(highlights) == maxHighlights {
			return highlights, true
		}
	}
	return highlights, false
}

func tokenToEventKind(t logparse.Token) EventKind {
	switch t {
	case logparse.TokenHTTPError:
		return EventHTTPError
	case logparse.TokenCLIError, logparse.TokenFailedLine:
		return EventError
	case logparse.TokenPlain, logparse.TokenBlank, logparse.TokenVersionLine,
		logparse.TokenTableRow, logparse.TokenSummaryMarker, logparse.TokenErrorsMarker,
		logparse.TokenExitCode:
		return ""
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// Internal: message joining and footer assembly
// ---------------------------------------------------------------------------

func joinMessages(tokens []logparse.TokenizedLine) string {
	if len(tokens) == 0 {
		return ""
	}
	parts := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		parts = append(parts, tok.Message)
	}
	return strings.Join(parts, "\n")
}

func joinFooter(summaryTokens, resultTokens []logparse.TokenizedLine) string {
	var footerTokens []logparse.TokenizedLine
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
