package lifecycle_workflow

import (
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/logging"
	"github.com/snyk/go-application-framework/pkg/workflow/catalog"
)

// INTERIM: replace with the released error-catalog error (CLI-2044), which this mirrors (SNYK-CLI-0036).
func installOrUninstallFailedError(detail string, cause error) snyk_errors.Error {
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
		Cause:          cause,
	}
}

func failureCauses(failures []catalog.StepFailure) error {
	errs := make([]error, 0, len(failures))
	for _, failure := range failures {
		errs = append(errs, failure.Err)
	}
	return errors.Join(errs...)
}

func failureDetail(config configuration.Configuration, failures []catalog.StepFailure) string {
	scrubDict := logging.GetScrubDictFromConfig(config)
	lines := make([]string, 0, len(failures))
	for _, failure := range failures {
		message := string(logging.ScrubValue([]byte(causeText(failure.Err)), scrubDict))
		lines = append(lines, failure.ID.String()+": "+strings.Join(strings.Fields(message), " "))
	}
	return strings.Join(lines, "\n")
}

// causeText includes the detail of catalog errors, whose message is only the title.
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
