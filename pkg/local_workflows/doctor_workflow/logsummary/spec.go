// Package logsummary turns a Snyk CLI debug log into a structured, human-
// readable diagnostic report. It configures the generic logparse engine with
// the Snyk-specific vocabulary (markers, prefixes, notable-event patterns) and
// a version-keyed registry of format specs.
package logsummary

import (
	"regexp"
	"strings"

	"github.com/snyk/go-application-framework/pkg/local_workflows/doctor_workflow/logparse"
)

// Snyk CLI debug-log patterns.
var (
	// basePrefixRe matches the Snyk CLI debug prefix, e.g. "2026-06-10T13:10:38Z main - ".
	basePrefixRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\S+ \S+ - ?`)
	// baseTableRe identifies rows in the CLI environment table so unknown fields
	// added by future CLI versions still stay in the Environment section.
	baseTableRe = regexp.MustCompile(`^[A-Za-z][\w .-]*:`)
	// responseRe matches an HTTP response line with a 4xx/5xx status.
	responseRe = regexp.MustCompile(`^< response \[0x[0-9a-fA-F]+\]:\s*[45]\d{2}\b`)
)

// versionPrefixes are the field labels that carry the CLI version, tried in order.
var versionPrefixes = []string{"Version:", "CLI Version:"}

// baseLexer is the tokenization rule set for the current (base) log format.
var baseLexer = logparse.NewLexerSpec(
	logparse.WithLinePrefixRe(basePrefixRe),
	logparse.WithSummaryMarker("------------ Summary ------------"),
	logparse.WithErrorsMarker("------------ Errors ------------"),
	logparse.WithVersionPrefix("Version:"),
	logparse.WithExitCodePrefix("Exit Code:"),
	logparse.WithTableRowRe(baseTableRe),
	logparse.WithClassifiers(
		logparse.NewBodyClassifier(func(msg string) bool { return responseRe.MatchString(msg) }, logparse.TokenHTTPError),
		logparse.NewBodyClassifier(func(msg string) bool { return strings.HasPrefix(msg, "< error:") }, logparse.TokenCLIError),
		logparse.NewBodyClassifier(func(msg string) bool { return strings.HasPrefix(msg, "Failed ") }, logparse.TokenFailedLine),
	),
)

// baseLandmarks maps structural anchors to the sections they open.
var baseLandmarks = []logparse.LandmarkRule{
	logparse.NewLandmarkRule(logparse.TokenVersionLine, logparse.SectionHeader),
	logparse.NewLandmarkRule(logparse.TokenSummaryMarker, logparse.SectionSummary),
	logparse.NewLandmarkRule(logparse.TokenErrorsMarker, logparse.SectionResult),
	logparse.NewLandmarkRule(logparse.TokenExitCode, logparse.SectionResult),
}

// BaseSpec is the fallback format spec that matches all CLI versions. Newer
// specs derived via logparse.DeriveFormat should be prepended to registry so
// they are matched before this catch-all.
var BaseSpec = logparse.NewFormatSpec("base", logparse.VersionRange("0.0.0", ""), baseLexer, baseLandmarks)

// registry lists known format specs, newest-first. Detection returns the first
// spec whose version constraint contains the log's declared version.
var registry = []logparse.FormatSpec{BaseSpec}

// newDetector builds a detector over the current registry. It is constructed
// per call so tests that swap the registry take effect.
func newDetector() *logparse.Detector {
	return logparse.NewDetector(basePrefixRe, versionPrefixes, registry, BaseSpec)
}
