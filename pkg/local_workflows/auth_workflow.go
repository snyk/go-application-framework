package localworkflows

import (
	"fmt"
	"os"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	workflowNameAuth  = "auth"
	headlessFlag      = "headless"
	authTypeParameter = "auth-type"
	authTypeOAuth     = "oauth"
	authTypeToken     = "token"
)

// define a new workflow identifier for this workflow
var (
	WORKFLOWID_AUTH workflow.Identifier = workflow.NewWorkflowIdentifier(workflowNameAuth)
	Auth                                = &authWorkflow{
		Workflow: &workflow.Workflow{
			Name:    workflowNameAuth,
			Visible: true,
			Flags: workflow.Flags{
				workflow.Flag[string]{
					Name:  authTypeParameter,
					Usage: fmt.Sprintf("Authentication type (%s, %s)", authTypeToken, authTypeOAuth),

					DefaultValue: "",
				},
				workflow.Flag[bool]{
					Name:         headlessFlag,
					Usage:        "Enable headless OAuth authentication",
					DefaultValue: false,
				},
			},
		},
	}
)

type authWorkflow struct {
	*workflow.Workflow
}

// InitAuth initialises the auth workflow before registering it with the engine.
// Deprecated: use `workflow.Register(AuthWorkflow, engine)` directly.
func InitAuth(engine workflow.Engine) error {
	// Only register if the OAuth flow is ready.
	if !engine.GetConfiguration().GetBool(configuration.FF_OAUTH_AUTH_FLOW_ENABLED) {
		return nil
	}
	return workflow.Register(Auth, engine)
}

func (a *authWorkflow) Entrypoint(invocationCtx workflow.InvocationContext, input []workflow.Data) ([]workflow.Data, error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	engine := invocationCtx.GetEngine()
	logger := a.Logger(invocationCtx)

	var oauthEnabled bool
	switch config.GetString(authTypeParameter) {
	case authTypeOAuth:
		oauthEnabled = true

	case authTypeToken:
		oauthEnabled = false

	default:
		oauthEnabled = auth.IsKnownOAuthEndpoint(config.GetString(configuration.API_URL))
	}

	logger.Println("OAuth enabled:", oauthEnabled)

	if oauthEnabled { // OAUTH flow
		headless := config.GetBool(headlessFlag)
		logger.Println("Headless:", headless)

		httpClient := invocationCtx.GetNetworkAccess().GetUnauthorizedHttpClient()
		authenticator := auth.NewOAuth2AuthenticatorWithOpts(
			config,
			auth.WithHttpClient(httpClient),
			auth.WithOpenBrowserFunc(OpenBrowser),
			auth.WithShutdownServerFunc(auth.ShutdownServer),
		)
		if err := authenticator.Authenticate(); err != nil {
			return nil, err
		}

		fmt.Println(auth.AUTHENTICATED_MESSAGE)

	} else { // LEGACY flow
		config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])
		config.Set(configuration.WORKFLOW_USE_STDIO, true)
		_, legacyCLIError := engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
		if legacyCLIError != nil {
			return nil, legacyCLIError
		}
	}

	return nil, nil
}

const templateConsoleMessage = `
Now redirecting you to our auth page, go ahead and log in,
and once the auth is complete, return to this prompt and you'll
be ready to start using snyk.

If you can't wait use this url:
%s
`

func OpenBrowser(authUrl string) {
	fmt.Println(fmt.Sprintf(templateConsoleMessage, authUrl))
	auth.OpenBrowser(authUrl)
}
