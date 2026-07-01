package logparse

import "regexp"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// TokenizedLine is a raw log line enriched with its token classification.
type TokenizedLine struct {
	Number       int
	RawText      string
	Message      string
	HasCLIPrefix bool
	Token        Token
}

// BodyClassifier maps a matching function to a token type for body-line classification.
type BodyClassifier struct {
	Match func(msg string) bool
	Token Token
}

// LexerSpec defines the per-version rules for tokenizing log lines.
type LexerSpec struct {
	LinePrefixRe    *regexp.Regexp
	SummaryMarker   string
	ErrorsMarker    string
	VersionPrefix   string
	ExitCodePrefix  string
	TableRowRe      *regexp.Regexp
	BodyClassifiers []BodyClassifier
}

// LexerOption is a functional option applied when building or deriving a LexerSpec.
type LexerOption func(*LexerSpec)

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

// NewTokenizedLine builds a TokenizedLine.
func NewTokenizedLine(number int, rawText, message string, hasCLIPrefix bool, token Token) TokenizedLine {
	return TokenizedLine{
		Number:       number,
		RawText:      rawText,
		Message:      message,
		HasCLIPrefix: hasCLIPrefix,
		Token:        token,
	}
}

// NewBodyClassifier builds a BodyClassifier.
func NewBodyClassifier(match func(msg string) bool, token Token) BodyClassifier {
	return BodyClassifier{Match: match, Token: token}
}

// NewLexerSpec builds a LexerSpec from the given options, starting from an
// empty spec.
func NewLexerSpec(opts ...LexerOption) LexerSpec {
	var spec LexerSpec
	for _, opt := range opts {
		opt(&spec)
	}
	return spec
}

// ---------------------------------------------------------------------------
// LexerOption constructors
// ---------------------------------------------------------------------------

func WithSummaryMarker(m string) LexerOption {
	return func(s *LexerSpec) { s.SummaryMarker = m }
}

func WithErrorsMarker(m string) LexerOption {
	return func(s *LexerSpec) { s.ErrorsMarker = m }
}

func WithVersionPrefix(p string) LexerOption {
	return func(s *LexerSpec) { s.VersionPrefix = p }
}

func WithExitCodePrefix(p string) LexerOption {
	return func(s *LexerSpec) { s.ExitCodePrefix = p }
}

func WithLinePrefixRe(re *regexp.Regexp) LexerOption {
	return func(s *LexerSpec) { s.LinePrefixRe = re }
}

func WithTableRowRe(re *regexp.Regexp) LexerOption {
	return func(s *LexerSpec) { s.TableRowRe = re }
}

// WithClassifiers replaces the body classifiers with a copy of the given set.
func WithClassifiers(classifiers ...BodyClassifier) LexerOption {
	return func(s *LexerSpec) {
		s.BodyClassifiers = append([]BodyClassifier{}, classifiers...)
	}
}

// WithExtraClassifier prepends a classifier so it takes priority over inherited ones.
func WithExtraClassifier(match func(string) bool, token Token) LexerOption {
	return func(s *LexerSpec) {
		s.BodyClassifiers = append(
			[]BodyClassifier{NewBodyClassifier(match, token)},
			s.BodyClassifiers...,
		)
	}
}

// ---------------------------------------------------------------------------
// DeriveLexer
// ---------------------------------------------------------------------------

// DeriveLexer creates a new LexerSpec by copying parent and applying overrides.
// The BodyClassifiers slice is deep-copied so mutations don't leak to the parent.
func DeriveLexer(parent LexerSpec, opts ...LexerOption) LexerSpec {
	spec := parent
	spec.BodyClassifiers = append([]BodyClassifier{}, parent.BodyClassifiers...)
	for _, opt := range opts {
		opt(&spec)
	}
	return spec
}

// ---------------------------------------------------------------------------
// Tokenize (Phase 1 of the pipeline)
// ---------------------------------------------------------------------------

// Tokenize classifies each raw line into a TokenizedLine using the given spec.
func Tokenize(spec LexerSpec, rawLines []string) []TokenizedLine {
	lines := make([]TokenizedLine, 0, len(rawLines))
	for i, raw := range rawLines {
		raw = stripCR(raw)
		msg, hasPrefix := stripLinePrefix(spec.LinePrefixRe, raw)
		tok := classifyToken(spec, msg, hasPrefix)
		lines = append(lines, NewTokenizedLine(i+1, raw, msg, hasPrefix, tok))
	}
	return lines
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func stripCR(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\r' {
		return s[:len(s)-1]
	}
	return s
}

func stripLinePrefix(re *regexp.Regexp, line string) (message string, hasPrefix bool) {
	if re == nil {
		return line, false
	}
	if loc := re.FindStringIndex(line); loc != nil {
		return line[loc[1]:], true
	}
	return line, false
}

func classifyToken(spec LexerSpec, msg string, hasPrefix bool) Token {
	trimmed := trimSpace(msg)
	if trimmed == "" {
		return TokenBlank
	}

	if trimmed == spec.SummaryMarker {
		return TokenSummaryMarker
	}
	if trimmed == spec.ErrorsMarker {
		return TokenErrorsMarker
	}

	if hasFieldPrefix(msg, spec.VersionPrefix) {
		return TokenVersionLine
	}
	if hasFieldPrefix(msg, spec.ExitCodePrefix) {
		return TokenExitCode
	}

	// Body classifiers and table-row detection only apply to prefixed CLI lines.
	if hasPrefix {
		for _, c := range spec.BodyClassifiers {
			if c.Match(msg) {
				return c.Token
			}
		}
		if spec.TableRowRe != nil && isTableRowLike(msg, spec.TableRowRe) {
			return TokenTableRow
		}
	}

	return TokenPlain
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func hasFieldPrefix(msg, prefix string) bool {
	return prefix != "" && len(msg) >= len(prefix) && msg[:len(prefix)] == prefix
}

func isTableRowLike(msg string, tableRowRe *regexp.Regexp) bool {
	if msg == "" {
		return false
	}
	if msg[0] == ' ' || msg[0] == '\t' {
		return true
	}
	return tableRowRe.MatchString(msg)
}
