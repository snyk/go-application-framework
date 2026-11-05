package lifecycle_workflow

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/go-application-framework/pkg/workflow/catalog"
)

// Unit: the interim error carries the fields designed for SNYK-CLI-0036, and the given detail unchanged.
func Test_installOrUninstallFailedError_MatchesCatalogDesign(t *testing.T) {
	err := installOrUninstallFailedError("flw://step: boom")

	assert.Equal(t, "SNYK-CLI-0036", err.ErrorCode)
	assert.Equal(t, "https://docs.snyk.io/scan-with-snyk/error-catalog#snyk-cli-0036", err.Type)
	assert.Equal(t, "Install or uninstall failed", err.Title)
	assert.Equal(t, 0, err.StatusCode)
	assert.Equal(t, "ACTIONABLE", err.Classification)
	assert.Equal(t, "error", err.Level)
	assert.Equal(t, []string{"https://docs.snyk.io/snyk-cli/debugging-the-snyk-cli"}, err.Links)
	assert.Equal(t, "One or more steps provided by extensions failed, so the install or uninstall did not complete. "+
		"A failed step does not stop the other steps. "+
		"The error details list each failed step on its own line as `step ID: message`. "+
		"Fix the cause named in each message, then run the command again. "+
		"See [Snyk CLI debugging](https://docs.snyk.io/snyk-cli/debugging-the-snyk-cli).", err.Description)
	assert.Equal(t, "flw://step: boom", err.Detail)
	assert.NotEmpty(t, err.ID)
}

// Unit: the detail has one line per failed step as "<step ID>: <message>". Each message is flattened to one line, and
// redacted with the configured secrets before it is shown.
func Test_failureDetail_OneLinePerStepFlattenedAndRedacted(t *testing.T) {
	const secret = "secret-token-value-1234"
	config := configuration.NewWithOpts()
	config.Set(configuration.AUTHENTICATION_TOKEN, secret)

	failures := []catalog.StepFailure{
		{ID: workflow.NewWorkflowIdentifier("first"), Message: "line one\nline two with " + secret},
		{ID: workflow.NewWorkflowIdentifier("second"), Message: "plain"},
	}

	detail := failureDetail(config, failures)

	lines := strings.Split(detail, "\n")
	assert.Len(t, lines, 2)
	assert.True(t, strings.HasPrefix(lines[0], "flw://first: line one line two with "))
	assert.Equal(t, "flw://second: plain", lines[1])
	assert.NotContains(t, detail, secret)
}

// Unit: a failure without a message still yields a step line with its ID.
func Test_failureDetail_KeepsStepIDWhenMessageIsEmpty(t *testing.T) {
	failures := []catalog.StepFailure{{ID: workflow.NewWorkflowIdentifier("empty"), Message: ""}}

	assert.Equal(t, "flw://empty: ", failureDetail(configuration.NewWithOpts(), failures))
}
