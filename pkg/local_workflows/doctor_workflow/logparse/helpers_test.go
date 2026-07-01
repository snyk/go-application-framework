package logparse

import (
	"regexp"
	"strings"
)

// Synthetic specs used across the engine tests. They mirror a Snyk-style debug
// log but live here so the engine tests stay independent of any concrete
// application configuration.

var (
	testPrefixRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\S+ \S+ - ?`)
	testTableRe    = regexp.MustCompile(`^[A-Za-z][\w .-]*:`)
	testResponseRe = regexp.MustCompile(`^< response \[0x[0-9a-fA-F]+\]:\s*[45]\d{2}\b`)
)

var testLexer = NewLexerSpec(
	WithLinePrefixRe(testPrefixRe),
	WithSummaryMarker("------------ Summary ------------"),
	WithErrorsMarker("------------ Errors ------------"),
	WithVersionPrefix("Version:"),
	WithExitCodePrefix("Exit Code:"),
	WithTableRowRe(testTableRe),
	WithClassifiers(
		NewBodyClassifier(func(msg string) bool { return testResponseRe.MatchString(msg) }, TokenHTTPError),
		NewBodyClassifier(func(msg string) bool { return strings.HasPrefix(msg, "< error:") }, TokenCLIError),
		NewBodyClassifier(func(msg string) bool { return strings.HasPrefix(msg, "Failed ") }, TokenFailedLine),
	),
)

var testLandmarks = []LandmarkRule{
	NewLandmarkRule(TokenVersionLine, SectionHeader),
	NewLandmarkRule(TokenSummaryMarker, SectionSummary),
	NewLandmarkRule(TokenErrorsMarker, SectionResult),
	NewLandmarkRule(TokenExitCode, SectionResult),
}

var testSpec = NewFormatSpec("test", VersionRange("0.0.0", ""), testLexer, testLandmarks)

func makeTok(number int, token Token, msg string) TokenizedLine {
	return NewTokenizedLine(number, "", msg, true, token)
}
