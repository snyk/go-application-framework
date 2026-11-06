package lifecycle_workflow

import (
	"errors"
	"fmt"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/go-application-framework/pkg/workflow/catalog"
)

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

func Test_failureDetail_RendersOneLinePerStep(t *testing.T) {
	catalogErr := snyk_errors.Error{Title: "Access expired", Detail: "the access\nexpired"}
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"plain error", errors.New("plain"), "flw://step: plain"},
		{"multi-line message is flattened", errors.New("line one\nline two"), "flw://step: line one line two"},
		{"empty message keeps the step ID", errors.New(""), "flw://step: "},
		{"catalog error uses title and detail", catalogErr, "flw://step: Access expired: the access expired"},
		{"wrapped catalog error uses title and detail", fmt.Errorf("refresh: %w", catalogErr), "flw://step: Access expired: the access expired"},
		{"catalog error without detail uses title", snyk_errors.Error{Title: "Only title"}, "flw://step: Only title"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			failures := []catalog.StepFailure{{ID: workflow.NewWorkflowIdentifier("step"), Err: tt.err}}

			assert.Equal(t, tt.want, failureDetail(configuration.NewWithOpts(), failures))
		})
	}
}

func Test_failureDetail_JoinsStepsWithNewlines(t *testing.T) {
	failures := []catalog.StepFailure{
		{ID: workflow.NewWorkflowIdentifier("first"), Err: errors.New("one")},
		{ID: workflow.NewWorkflowIdentifier("second"), Err: errors.New("two")},
	}

	assert.Equal(t, "flw://first: one\nflw://second: two", failureDetail(configuration.NewWithOpts(), failures))
}

func Test_failureDetail_RedactsSecrets(t *testing.T) {
	const secret = "secret-token-value-1234"
	config := configuration.NewWithOpts()
	config.Set(configuration.AUTHENTICATION_TOKEN, secret)
	failures := []catalog.StepFailure{
		{ID: workflow.NewWorkflowIdentifier("plain"), Err: errors.New("failed with " + secret)},
		{ID: workflow.NewWorkflowIdentifier("catalog"), Err: snyk_errors.Error{Title: "Expired", Detail: "token " + secret}},
	}

	detail := failureDetail(config, failures)

	assert.NotContains(t, detail, secret)
	assert.Contains(t, detail, "flw://plain: failed with ")
	assert.Contains(t, detail, "flw://catalog: Expired: token ")
}
