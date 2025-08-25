package localworkflows

import (
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/ui"
	pgk_utils "github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	workflowNameAuth  = "auth"
	headlessFlag      = "headless"
	AuthTypeParameter = "auth-type"
)

var authTypeDescription = fmt.Sprint("Authentication type (", auth.AUTH_TYPE_TOKEN, ", ", auth.AUTH_TYPE_OAUTH, ")")

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
	config.String(AuthTypeParameter, "", authTypeDescription)
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
	globalConfig := engine.GetConfiguration()

	// cache always interferes with auth
	globalConfig.ClearCache()

	// make sure the updated environment is forwarded to global config
	defer globalConfig.ClearCache()

	httpClient := invocationCtx.GetNetworkAccess().GetUnauthorizedHttpClient()
	authenticator := auth.NewOAuth2AuthenticatorWithOpts(
		config,
		auth.WithHttpClient(httpClient),
		auth.WithOpenBrowserFunc(OpenBrowser),
		auth.WithShutdownServerFunc(auth.ShutdownServer),
		auth.WithLogger(logger),
	)

	err = AuthEntryPointDI(invocationCtx, logger, engine, authenticator)
	return nil, err
}

func autoDetectAuthType(config configuration.Configuration) string {
	// testing if an API token was specified
	token := config.GetString(ConfigurationNewAuthenticationToken)
	if len(token) > 0 && auth.IsAuthTypeToken(token) {
		return auth.AUTH_TYPE_TOKEN
	}

	// currently the auth workflow defaults to traditional token auth when an IDE environment is detected
	// this will need to change if IDEs want to invoke this workflow for oauth/PAT
	integration := config.GetString(configuration.INTEGRATION_NAME)
	if pgk_utils.IsSnykIde(integration) {
		return auth.AUTH_TYPE_TOKEN
	}

	// check if auth type is PAT
	if len(token) > 0 && auth.IsAuthTypePAT(token) {
		return auth.AUTH_TYPE_PAT
	}

	return auth.AUTH_TYPE_OAUTH
}

func AuthEntryPointDI(invocationCtx workflow.InvocationContext, logger *zerolog.Logger, engine workflow.Engine, authenticator auth.Authenticator) (err error) {
	analytics := invocationCtx.GetAnalytics()
	globalConfig := engine.GetConfiguration()
	config := invocationCtx.GetConfiguration()

	authType := config.GetString(AuthTypeParameter)
	if len(authType) == 0 {
		authType = autoDetectAuthType(config)
	}

	logger.Printf("Authentication Type: %s", authType)
	analytics.AddExtensionStringValue(AuthTypeParameter, authType)

	existingSnykToken := config.GetString(configuration.AUTHENTICATION_TOKEN)
	// always attempt to clear existing tokens before triggering auth for current config clone and global config
	logger.Print("Unset existing auth keys")
	config.Unset(configuration.AUTHENTICATION_TOKEN)
	config.Unset(auth.CONFIG_KEY_OAUTH_TOKEN)
	globalConfig.Unset(configuration.AUTHENTICATION_TOKEN)
	globalConfig.Unset(auth.CONFIG_KEY_OAUTH_TOKEN)

	if strings.EqualFold(authType, auth.AUTH_TYPE_OAUTH) { // OAUTH flow
		headless := config.GetBool(headlessFlag)
		logger.Printf("Headless: %v", headless)

		err = authenticator.Authenticate()
		if err != nil {
			return err
		}

		newToken := config.Get(auth.CONFIG_KEY_OAUTH_TOKEN)
		globalConfig.Set(auth.CONFIG_KEY_OAUTH_TOKEN, newToken)

		err = ui.DefaultUi().Output(auth.AUTHENTICATED_MESSAGE)
		if err != nil {
			logger.Debug().Err(err).Msg("Failed to output authenticated message")
		}
	} else if strings.EqualFold(authType, auth.AUTH_TYPE_PAT) { // PAT flow
		globalConfig.PersistInStorage(auth.CONFIG_KEY_TOKEN)
		pat := config.GetString(ConfigurationNewAuthenticationToken)

		logger.Print("Validating pat")
		whoamiConfig := config.Clone()
		whoamiConfig.ClearCache()
		// we don't want to use the cache here, so this is a workaround
		whoamiConfig.Set(configuration.FLAG_EXPERIMENTAL, true)
		whoamiConfig.Set(configuration.AUTHENTICATION_TOKEN, pat)
		_, whoamiErr := engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("whoami"), whoamiConfig)
		if whoamiErr != nil {
			// reset config file
			if len(existingSnykToken) > 0 {
				config.Set(auth.CONFIG_KEY_TOKEN, existingSnykToken)
			}
			return whoamiErr
		}

		logger.Print("Validation successful; set pat credentials in config")
		// we don't want to use the cache here, so this is a workaround
		globalConfig.ClearCache()
		globalConfig.Set(auth.CONFIG_KEY_TOKEN, pat)

		err = ui.DefaultUi().Output(auth.AUTHENTICATED_MESSAGE)
		if err != nil {
			logger.Debug().Err(err).Msg("Failed to output authenticated message")
		}
	} else { // LEGACY flow
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
