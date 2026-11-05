package lifecycle_workflow

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/go-application-framework/pkg/workflow/catalog"
)

// Unit: the interim error carries the fields designed for SNYK-CLI-0036, the given detail unchanged, and the given cause.
func Test_installOrUninstallFailedError_MatchesCatalogDesign(t *testing.T) {
	cause := errors.New("boom")
	err := installOrUninstallFailedError("flw://step: boom", cause)

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
	assert.ErrorIs(t, err, cause)
}

// Unit: the detail has one line per failed step as "<step ID>: <cause>". Each cause is flattened to one line, and
// redacted with the configured secrets before it is shown.
func Test_failureDetail_OneLinePerStepFlattenedAndRedacted(t *testing.T) {
	const secret = "secret-token-value-1234"
	config := configuration.NewWithOpts()
	config.Set(configuration.AUTHENTICATION_TOKEN, secret)

	failures := []catalog.StepFailure{
		{ID: workflow.NewWorkflowIdentifier("first"), Err: errors.New("line one\nline two with " + secret)},
		{ID: workflow.NewWorkflowIdentifier("second"), Err: errors.New("plain")},
	}

	detail := failureDetail(config, failures)

	lines := strings.Split(detail, "\n")
	assert.Len(t, lines, 2)
	assert.True(t, strings.HasPrefix(lines[0], "flw://first: line one line two with "))
	assert.Equal(t, "flw://second: plain", lines[1])
	assert.NotContains(t, detail, secret)
}

// Unit: a failure whose message is empty still yields a step line with its ID.
func Test_failureDetail_KeepsStepIDWhenMessageIsEmpty(t *testing.T) {
	failures := []catalog.StepFailure{{ID: workflow.NewWorkflowIdentifier("empty"), Err: errors.New("")}}

	assert.Equal(t, "flw://empty: ", failureDetail(configuration.NewWithOpts(), failures))
}

// Unit: a Snyk error-catalog error contributes its title and its detail, which names the cause. The same holds when the
// catalog error is wrapped. Its detail is redacted like any other text.
func Test_failureDetail_UsesTitleAndDetailOfCatalogError(t *testing.T) {
	const secret = "secret-token-value-5678"
	config := configuration.NewWithOpts()
	config.Set(configuration.AUTHENTICATION_TOKEN, secret)

	catalogErr := snyk_errors.Error{Title: "Access expired", Detail: "the access\nfor " + secret + " expired"}
	failures := []catalog.StepFailure{
		{ID: workflow.NewWorkflowIdentifier("direct"), Err: catalogErr},
		{ID: workflow.NewWorkflowIdentifier("wrapped"), Err: fmt.Errorf("refresh: %w", catalogErr)},
		{ID: workflow.NewWorkflowIdentifier("no-detail"), Err: snyk_errors.Error{Title: "Only title"}},
	}

	detail := failureDetail(config, failures)

	lines := strings.Split(detail, "\n")
	assert.Len(t, lines, 3)
	assert.True(t, strings.HasPrefix(lines[0], "flw://direct: Access expired: the access for "))
	assert.True(t, strings.HasPrefix(lines[1], "flw://wrapped: Access expired: the access for "))
	assert.Equal(t, "flw://no-detail: Only title", lines[2])
	assert.NotContains(t, detail, secret)
}
