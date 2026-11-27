package lifecycle_workflow

import (
	"errors"
	"regexp"
	"strings"
	"unicode"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/logging"
	"github.com/snyk/go-application-framework/pkg/workflow/catalog"
)

// maxStepTextRunes limits each step ID and each step message in the detail of the error.
const maxStepTextRunes = 500

// ansiEscape matches the escape sequences that color, link or move text: CSI sequences, OSC sequences ended by BEL or
// ST, DCS, SOS, PM and APC strings ended by ST, and all other escapes with their intermediate bytes, such as ESC c.
var ansiEscape = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[PX^_][^\x1b]*\x1b\\|[ -/]*[0-~])`)

// installOrUninstallFailedError is the released SNYK-CLI-0038 error for steps of an install or uninstall that failed.
// The cause keeps the original errors of the failed steps reachable with errors.Is and errors.As.
func installOrUninstallFailedError(detail string, cause error) snyk_errors.Error {
	return cli.NewInstallOrUninstallFailedError(detail, snyk_errors.WithCause(cause))
}

// failureCauses joins the original errors of the failed steps, so errors.Is and errors.As reach each of them.
func failureCauses(failures []catalog.StepFailure) error {
	errs := make([]error, 0, len(failures))
	for _, failure := range failures {
		errs = append(errs, failure.Err)
	}
	return errors.Join(errs...)
}

// failureDetail renders each failed step on its own line as "<step ID>: <cause>". Step text comes from extensions, so it
// is cleaned of escape sequences and control characters first. The message is then redacted with the secrets of the
// configuration, and both the ID and the message are flattened onto one line and truncated last. Redacting before
// truncating keeps a secret that straddles the limit from showing as a prefix.
func failureDetail(config configuration.Configuration, failures []catalog.StepFailure) string {
	scrubDict := logging.GetScrubDictFromConfig(config)
	lines := make([]string, 0, len(failures))
	for _, failure := range failures {
		id := truncateRunes(flatten(cleanText(failure.ID.String())), maxStepTextRunes)
		message := logging.ScrubValue([]byte(cleanText(causeText(failure.Err))), scrubDict)
		lines = append(lines, id+": "+truncateRunes(flatten(string(message)), maxStepTextRunes))
	}
	return strings.Join(lines, "\n")
}

// cleanText removes ANSI escape sequences, control characters and format characters, such as a zero-width space or a
// bidi override. Whitespace, such as a line break or a tab, becomes a space.
func cleanText(text string) string {
	text = ansiEscape.ReplaceAllString(text, "")
	return strings.Map(func(r rune) rune {
		switch {
		case unicode.IsSpace(r):
			return ' '
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r):
			return -1
		default:
			return r
		}
	}, text)
}

// flatten collapses each run of whitespace into one space, so the text fits on one line.
func flatten(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// truncateRunes keeps the first limit runes of text and appends an ellipsis when it cuts text short.
func truncateRunes(text string, limit int) string {
	runes := []rune(text)
	if len(runes) <= limit {
		return text
	}
	return string(runes[:limit]) + "…"
}

// causeText returns the text that names the cause of a failed step. A Snyk error-catalog error contributes its title and
// its detail, because its message is only the title. Any other error contributes its message.
func causeText(err error) string {
	var catalogErr snyk_errors.Error
	if errors.As(err, &catalogErr) {
		if catalogErr.Detail == "" {
			return catalogErr.Title
		}
		return catalogErr.Title + ": " + catalogErr.Detail
	}
	return err.Error()
}
