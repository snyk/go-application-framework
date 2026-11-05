package lifecycle_workflow

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/go-application-framework/pkg/workflow/catalog"
)

// Unit: the error is the released SNYK-CLI-0038 error, with the given detail unchanged and the given cause.
func Test_installOrUninstallFailedError_IsReleasedCatalogError(t *testing.T) {
	cause := errors.New("boom")
	err := installOrUninstallFailedError("flw://step: boom", cause)

	assert.Equal(t, "SNYK-CLI-0038", err.ErrorCode)
	assert.Equal(t, "https://docs.snyk.io/scan-with-snyk/error-catalog#snyk-cli-0038", err.Type)
	assert.Equal(t, "Install or uninstall failed", err.Title)
	assert.Equal(t, "flw://step: boom", err.Detail)
	assert.NotEmpty(t, err.ID)
	assert.ErrorIs(t, err, cause)

	released := cli.NewInstallOrUninstallFailedError("")
	assert.Equal(t, released.Description, err.Description)
	assert.Equal(t, released.StatusCode, err.StatusCode)
	assert.Equal(t, released.Classification, err.Classification)
	assert.Equal(t, released.Level, err.Level)
	assert.Equal(t, released.Links, err.Links)
}

// Unit: step text is sanitized before it is shown. ANSI escape sequences are removed, and line breaks and tabs become
// spaces. Other control characters, including NUL and DEL, are dropped.
func Test_failureDetail_StripsAnsiAndControlCharacters(t *testing.T) {
	failures := []catalog.StepFailure{
		{ID: workflow.NewWorkflowIdentifier("color"), Err: errors.New("\x1b[31mred\x1b[0m failed")},
		{ID: workflow.NewWorkflowIdentifier("link"), Err: errors.New("see \x1b]8;;http://x\x07link\x1b]8;;\x07 end")},
		{ID: workflow.NewWorkflowIdentifier("controls"), Err: errors.New("a\r\nb\tc\x00d\x7fe")},
		{ID: workflow.NewWorkflowIdentifier("other"), Err: errors.New("\x1bc reset \x1b7 save \x1bPq#0\x1b\\dcs")},
	}

	lines := strings.Split(failureDetail(configuration.NewWithOpts(), failures), "\n")

	assert.Equal(t, []string{
		"flw://color: red failed",
		"flw://link: see link end",
		"flw://controls: a b cde",
		"flw://other: reset save dcs",
	}, lines)
}

// Unit: format characters, such as a zero-width space or a bidi override, are dropped, so they cannot hide a secret or
// reorder the text.
func Test_failureDetail_DropsFormatCharacters(t *testing.T) {
	failures := []catalog.StepFailure{
		{ID: workflow.NewWorkflowIdentifier("format"), Err: errors.New("a\u200bb\u202ec")},
	}

	assert.Equal(t, "flw://format: abc", failureDetail(configuration.NewWithOpts(), failures))
}

// Unit: a secret split by an escape sequence is redacted, because the escape sequence is removed before redaction.
func Test_failureDetail_RedactsSecretSplitByEscapeSequence(t *testing.T) {
	const secret = "secret-token-value-3456"
	config := configuration.NewWithOpts()
	config.Set(configuration.AUTHENTICATION_TOKEN, secret)

	failures := []catalog.StepFailure{
		{ID: workflow.NewWorkflowIdentifier("split"), Err: errors.New("secret-\x1b[0mtoken-value-3456")},
	}

	detail := failureDetail(config, failures)

	assert.NotContains(t, detail, "token-value")
	assert.NotContains(t, detail, "secret-")
}

// Unit: a step message and a step ID longer than 500 runes are cut to 500 runes and end with an ellipsis. A message of
// exactly 500 runes is kept whole.
func Test_failureDetail_TruncatesLongStepTextTo500Runes(t *testing.T) {
	longName := strings.Repeat("x", 600)
	longID := workflow.NewWorkflowIdentifier(longName).String()
	exact := strings.Repeat("é", 500)
	failures := []catalog.StepFailure{
		{ID: workflow.NewWorkflowIdentifier("long"), Err: errors.New(strings.Repeat("é", 600))},
		{ID: workflow.NewWorkflowIdentifier(longName), Err: errors.New("short")},
		{ID: workflow.NewWorkflowIdentifier("exact"), Err: errors.New(exact)},
	}

	lines := strings.Split(failureDetail(configuration.NewWithOpts(), failures), "\n")

	assert.Equal(t, "flw://long: "+exact+"…", lines[0])
	assert.Equal(t, string([]rune(longID)[:500])+"…: short", lines[1])
	assert.Equal(t, "flw://exact: "+exact, lines[2])
}

// Unit: the secrets are redacted before the text is cut, so a secret that straddles the limit does not leak as a prefix.
func Test_failureDetail_RedactsSecretBeforeTruncating(t *testing.T) {
	const secret = "secret-token-value-9012"
	config := configuration.NewWithOpts()
	config.Set(configuration.AUTHENTICATION_TOKEN, secret)

	failures := []catalog.StepFailure{
		{ID: workflow.NewWorkflowIdentifier("straddle"), Err: errors.New(strings.Repeat("a", 490) + secret)},
	}

	detail := failureDetail(config, failures)

	assert.NotContains(t, detail, secret[:8])
	assert.NotContains(t, detail, secret)
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
