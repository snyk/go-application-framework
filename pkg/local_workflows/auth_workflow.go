package localworkflows

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"

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

var authTypeDescription = fmt.Sprint("Authentication type (", authTypeToken, ", ", authTypeOAuth, ")")

const templateConsoleMessage = `
Now redirecting you to our auth page, go ahead and log in,
and once the auth is complete, return to this prompt and you'll
be ready to start using snyk.

If you can't wait use this url:
%s
`

// define a new workflow identifier for this workflow
var WORKFLOWID_AUTH workflow.Identifier = workflow.NewWorkflowIdentifier(workflowNameAuth)

// InitAuth initializes the auth workflow before registering it with the engine.
func InitAuth(engine workflow.Engine) error {
	if !engine.GetConfiguration().GetBool(configuration.FF_OAUTH_AUTH_FLOW_ENABLED) {
		return nil // Use legacy CLI for authentication for now, until OAuth is ready
	}
	config := pflag.NewFlagSet(workflowNameAuth, pflag.ExitOnError)
	config.String(authTypeParameter, "", authTypeDescription)
	config.Bool(headlessFlag, false, "Enable headless OAuth authentication")
	config.String(auth.PARAMETER_CLIENT_SECRET, "", "Client Credential Grant, client secret")
	config.String(auth.PARAMETER_CLIENT_ID, "", "Client Credential Grant, client id")

	_, err := engine.Register(WORKFLOWID_AUTH, workflow.ConfigurationOptionsFromFlagset(config), authEntryPoint)
	return err
}

func OpenBrowser(authUrl string) {
	fmt.Println(fmt.Sprintf(templateConsoleMessage, authUrl))
	auth.OpenBrowser(authUrl)
}

// authEntryPoint is the entry point for the auth workflow.
func authEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (_ []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetLogger()
	engine := invocationCtx.GetEngine()

	customEndpoint := config.GetString(configuration.API_URL)
	isOAuthSelected := config.GetString(authTypeParameter) == authTypeOAuth
	isTokenSelected := config.GetString(authTypeParameter) == authTypeToken
	var oauthEnabled bool
	if isOAuthSelected {
		oauthEnabled = true
	} else if isTokenSelected {
		oauthEnabled = false
	} else {
		oauthEnabled = auth.IsKnownOAuthEndpoint(customEndpoint)
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
		err = authenticator.Authenticate()
		if err != nil {
			return nil, err
		}

		fmt.Println(auth.AUTHENTICATED_MESSAGE)
	} else { // LEGACY flow
		config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])
		config.Set(configuration.WORKFLOW_USE_STDIO, true)
		config.Set(configuration.AUTHENTICATION_TOKEN, "") // unset token to avoid using it during authentication

		_, legacyCLIError := engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
		if legacyCLIError != nil {
			return nil, legacyCLIError
		}
	}

	return nil, err
}
