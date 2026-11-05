package lifecycle_workflow

import (
	"strings"

	"github.com/google/uuid"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/logging"
	"github.com/snyk/go-application-framework/pkg/workflow/catalog"
)

// installOrUninstallFailedError is the error for steps of an install or uninstall that failed.
//
// INTERIM: replace with the released error-catalog error (CLI-2044). Until it is released, this mirrors its design:
// SNYK-CLI-0036, with the details as one line per failed step.
func installOrUninstallFailedError(detail string) snyk_errors.Error {
	return snyk_errors.Error{
		ID:             uuid.NewString(),
		Type:           "https://docs.snyk.io/scan-with-snyk/error-catalog#snyk-cli-0036",
		Title:          "Install or uninstall failed",
		Description:    "One or more steps provided by extensions failed, so the install or uninstall did not complete. A failed step does not stop the other steps. The error details list each failed step on its own line as `step ID: message`. Fix the cause named in each message, then run the command again. See [Snyk CLI debugging](https://docs.snyk.io/snyk-cli/debugging-the-snyk-cli).",
		StatusCode:     0,
		ErrorCode:      "SNYK-CLI-0036",
		Classification: "ACTIONABLE",
		Links:          []string{"https://docs.snyk.io/snyk-cli/debugging-the-snyk-cli"},
		Level:          "error",
		Detail:         detail,
	}
}

// failureDetail renders each failed step on its own line as "<step ID>: <message>". A message is redacted with the
// secrets of the configuration, because step messages are not redacted, and then flattened onto one line.
func failureDetail(config configuration.Configuration, failures []catalog.StepFailure) string {
	scrubDict := logging.GetScrubDictFromConfig(config)
	lines := make([]string, 0, len(failures))
	for _, failure := range failures {
		message := string(logging.ScrubValue([]byte(failure.Message), scrubDict))
		lines = append(lines, failure.ID.String()+": "+strings.Join(strings.Fields(message), " "))
	}
	return strings.Join(lines, "\n")
}
