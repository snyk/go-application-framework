package localworkflows

import (
	"fmt"
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

// define a new workflow identifier for this workflow
var WORKFLOWID_AUTH workflow.Identifier = workflow.NewWorkflowIdentifier(workflowNameAuth)

// InitAuth initialises the auth workflow before registering it with the engine.
func InitAuth(engine workflow.Engine) error {
	config := pflag.NewFlagSet(workflowNameAuth, pflag.ExitOnError)
	config.String(authTypeParameter, "token", "Authentication type (token, oauth)")
	config.Bool(headlessFlag, false, "Enable headless OAuth authentication")

	_, err := engine.Register(WORKFLOWID_AUTH, workflow.ConfigurationOptionsFromFlagset(config), authEntryPoint)
	return err
}

func storeConfigValue(engine workflow.Engine, key string, value string) error {
	config := configuration.New()
	config.Set(configuration.RAW_CMD_ARGS, []string{"config", "set", key + "=" + value})
	config.Set(configuration.WORKFLOW_USE_STDIO, false)
	_, legacyCLIError := engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
	return legacyCLIError
}

// authEntryPoint is the entry point for the auth workflow.
func authEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (_ []workflow.Data, err error) {
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
		authenticator := auth.NewOAuth2Authenticator(config, httpClient)
		err = authenticator.Authenticate()
		if err != nil {
			return nil, err
		}

		fmt.Println("Successfully authenticated!")

		// TODO use configuration to store
		err = storeConfigValue(engine, auth.CONFIG_KEY_OAUTH_TOKEN, config.GetString(auth.CONFIG_KEY_OAUTH_TOKEN))
		if err != nil {
			return nil, err
		}
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
