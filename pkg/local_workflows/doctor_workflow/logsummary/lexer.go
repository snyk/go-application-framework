package logsummary

import "regexp"

type Token int

const (
	TokenPlain Token = iota
	TokenBlank
	TokenVersionLine
	TokenTableRow
	TokenHTTPError
	TokenCLIError
	TokenFailedLine
	TokenSummaryMarker
	TokenErrorsMarker
	TokenExitCode
)

type TokenizedLine struct {
	Number       int
	RawText      string
	Message      string
	HasCLIPrefix bool
	Token        Token
}

type BodyClassifier struct {
	Match func(msg string) bool
	Token Token
}

type LexerSpec struct {
	LinePrefixRe    *regexp.Regexp
	SummaryMarker   string
	ErrorsMarker    string
	VersionPrefix   string
	ExitCodePrefix  string
	TableRowRe      *regexp.Regexp
	BodyClassifiers []BodyClassifier
}

type LexerOption func(*LexerSpec)

func WithSummaryMarker(m string) LexerOption {
	return func(s *LexerSpec) { s.SummaryMarker = m }
}

func WithErrorsMarker(m string) LexerOption {
	return func(s *LexerSpec) { s.ErrorsMarker = m }
}

func WithExtraClassifier(match func(string) bool, token Token) LexerOption {
	return func(s *LexerSpec) {
		s.BodyClassifiers = append(
			[]BodyClassifier{{Match: match, Token: token}},
			s.BodyClassifiers...,
		)
	}
}

func WithLinePrefixRe(re *regexp.Regexp) LexerOption {
	return func(s *LexerSpec) { s.LinePrefixRe = re }
}

func WithVersionPrefix(p string) LexerOption {
	return func(s *LexerSpec) { s.VersionPrefix = p }
}

func DeriveLexer(parent LexerSpec, opts ...LexerOption) LexerSpec {
	spec := parent
	spec.BodyClassifiers = append([]BodyClassifier{}, parent.BodyClassifiers...)
	for _, opt := range opts {
		opt(&spec)
	}
	return spec
}

func tokenize(spec LexerSpec, rawLines []string) []TokenizedLine {
	lines := make([]TokenizedLine, 0, len(rawLines))
	for i, raw := range rawLines {
		raw = stripCR(raw)
		msg, hasPrefix := stripLinePrefix(spec.LinePrefixRe, raw)
		tok := classifyToken(spec, msg, hasPrefix)
		lines = append(lines, TokenizedLine{
			Number:       i + 1,
			RawText:      raw,
			Message:      msg,
			HasCLIPrefix: hasPrefix,
			Token:        tok,
		})
	}
	return lines
}

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

	if hasPrefix {
		if hasFieldPrefix(msg, spec.VersionPrefix) {
			return TokenVersionLine
		}
		if hasFieldPrefix(msg, spec.ExitCodePrefix) {
			return TokenExitCode
		}
		for _, c := range spec.BodyClassifiers {
			if c.Match(msg) {
				return c.Token
			}
		}
		if spec.TableRowRe != nil && isTableRowLike(msg, spec.TableRowRe) {
			return TokenTableRow
		}
	} else {
		if hasFieldPrefix(msg, spec.VersionPrefix) {
			return TokenVersionLine
		}
		if hasFieldPrefix(msg, spec.ExitCodePrefix) {
			return TokenExitCode
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
