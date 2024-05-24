package localworkflows

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/internal/utils"
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
var ConfigurationNewAuthenticationToken = "internal_new_snyk_token"

// InitAuth initializes the auth workflow before registering it with the engine.
func InitAuth(engine workflow.Engine) error {
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
	logger := invocationCtx.GetEnhancedLogger()
	engine := invocationCtx.GetEngine()

	httpClient := invocationCtx.GetNetworkAccess().GetUnauthorizedHttpClient()
	authenticator := auth.NewOAuth2AuthenticatorWithOpts(
		config,
		auth.WithHttpClient(httpClient),
		auth.WithOpenBrowserFunc(OpenBrowser),
		auth.WithShutdownServerFunc(auth.ShutdownServer),
	)

	err = entryPointDI(config, logger, engine, authenticator)
	return nil, err
}

func autoDetectAuthType(config configuration.Configuration) string {
	// testing if an API token was specified
	token := config.GetString(ConfigurationNewAuthenticationToken)
	if _, uuidErr := uuid.Parse(token); uuidErr == nil {
		return authTypeToken
	}

	integration := config.GetString(configuration.INTEGRATION_NAME)
	if utils.IsSnykIde(integration) {
		return authTypeToken
	}

	return authTypeOAuth
}

func entryPointDI(config configuration.Configuration, logger *zerolog.Logger, engine workflow.Engine, authenticator auth.Authenticator) (err error) {
	authType := config.GetString(authTypeParameter)
	if len(authType) == 0 {
		authType = autoDetectAuthType(config)
	}

	logger.Printf("Authentication Type: %s", authType)

	if strings.EqualFold(authType, authTypeOAuth) { // OAUTH flow
		logger.Printf("Unset legacy token key %q from config", configuration.AUTHENTICATION_TOKEN)
		config.Unset(configuration.AUTHENTICATION_TOKEN)

		headless := config.GetBool(headlessFlag)
		logger.Printf("Headless: %v", headless)

		err = authenticator.Authenticate()
		if err != nil {
			return err
		}

		fmt.Println(auth.AUTHENTICATED_MESSAGE)
	} else { // LEGACY flow
		logger.Printf("Unset oauth key %q from config", auth.CONFIG_KEY_OAUTH_TOKEN)
		config.Unset(auth.CONFIG_KEY_OAUTH_TOKEN)

		config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])
		config.Set(configuration.WORKFLOW_USE_STDIO, true)
		config.Set(configuration.AUTHENTICATION_TOKEN, "") // clear token to avoid using it during authentication

		_, legacyCLIError := engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
		if legacyCLIError != nil {
			return legacyCLIError
		}
	}

	return err
}
