// Package logparse provides a generic, version-aware engine for parsing
// line-oriented debug logs. It exposes a three-phase pipeline: a lexer that
// classifies each line into a Token, a landmark-based splitter that carves the
// token stream into named sections, and a format detector that selects the
// right rule set based on a log's declared version.
//
// The engine is intentionally free of any application-specific vocabulary:
// callers supply a LexerSpec (which patterns map to which tokens) and a set of
// LandmarkRules (which tokens delimit which sections). See the sibling
// logsummary package for a concrete configuration.
package logparse

// Token classifies a single log line.
type Token string

const (
	TokenPlain         Token = "plain"
	TokenBlank         Token = "blank"
	TokenVersionLine   Token = "version-line"
	TokenTableRow      Token = "table-row"
	TokenHTTPError     Token = "http-error"
	TokenCLIError      Token = "cli-error"
	TokenFailedLine    Token = "failed-line"
	TokenSummaryMarker Token = "summary-marker"
	TokenErrorsMarker  Token = "errors-marker"
	TokenExitCode      Token = "exit-code"
)
