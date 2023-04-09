package authworkflow

import (
	"fmt"
	"io"
	"os"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

const (
	workflowNameAuth  = "auth"
	headlessFlag      = "headless"
	authTypeParameter = "auth-type"
)

const templateConsoleMessage = `
Now redirecting you to our auth page, go ahead and log in,
and once the auth is complete, return to this prompt and you'll
be ready to start using snyk.

If you can't wait use this url:
%s
`

// WorkflowIdAuth define a new workflow identifier for this workflow
var WorkflowIdAuth = workflow.NewWorkflowIdentifier(workflowNameAuth)

// InitAuth initialises the auth workflow before registering it with the engine.
func InitAuth(engine workflow.Engine) error {
	config := pflag.NewFlagSet(workflowNameAuth, pflag.ExitOnError)
	config.String(authTypeParameter, "token", "Authentication type (token, oauth)")
	config.Bool(headlessFlag, false, "Enable headless OAuth authentication")

	authWorkflow := NewAuthWorkflow(os.Stdout)
	_, err := engine.Register(WorkflowIdAuth, workflow.ConfigurationOptionsFromFlagset(config), authWorkflow.authEntryPoint)
	if err != nil {
		return err
	}

	return InitRefresh(engine)
}

type AuthWorkflow struct {
	writer io.Writer
}

func NewAuthWorkflow(writer io.Writer) *AuthWorkflow {
	return &AuthWorkflow{
		writer: writer,
	}
}

func (aw *AuthWorkflow) OpenBrowser(authUrl string) {
	_, _ = fmt.Fprintf(aw.writer, templateConsoleMessage, authUrl)
	auth.OpenBrowser(authUrl)
}

func (aw *AuthWorkflow) authEntryPoint(
	invocationCtx workflow.InvocationContext,
	_ []workflow.Data,
) (_ []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetLogger()
	engine := invocationCtx.GetEngine()

	oauthEnabled := config.GetString(authTypeParameter) == "oauth"
	logger.Println("OAuth enabled:", oauthEnabled)

	if oauthEnabled { // OAUTH flow
		headless := config.GetBool(headlessFlag)
		logger.Println("Headless:", headless)

		httpClient := invocationCtx.GetNetworkAccess().GetUnauthorizedHttpClient()
		authenticator := auth.NewOAuth2AuthenticatorWithCustomFuncs(config, httpClient, aw.OpenBrowser, auth.ShutdownServer)
		err = authenticator.Authenticate()
		if err != nil {
			return nil, err
		}

		_, _ = fmt.Fprintln(aw.writer, auth.AUTHENTICATED_MESSAGE)

	} else { // LEGACY flow
		config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])
		config.Set(configuration.WORKFLOW_USE_STDIO, true)
		_, legacyCLIError := engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
		if legacyCLIError != nil {
			return nil, legacyCLIError
		}
	}

	return nil, err
}
