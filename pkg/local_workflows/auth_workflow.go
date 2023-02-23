package localworkflows

import (
	"fmt"
	"os"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
	"golang.org/x/oauth2"
)

const (
	workflowNameAuth = "auth"
	oauthFlag        = "oauth"
	headlessFlag     = "headless"
	endpointAuth     = "/user/me"
	apiVersionAuth   = "/v1"
)

// define a new workflow identifier for this workflow
var WORKFLOWID_AUTH workflow.Identifier = workflow.NewWorkflowIdentifier(workflowNameAuth)

// InitAuth initialises the auth workflow before registering it with the engine.
func InitAuth(engine workflow.Engine) error {
	config := pflag.NewFlagSet(workflowNameAuth, pflag.ExitOnError)
	config.Bool(oauthFlag, false, "Enable OAuth authentication")
	config.Bool(headlessFlag, false, "Enable headless OAuth authentication")

	_, err := engine.Register(WORKFLOWID_AUTH, workflow.ConfigurationOptionsFromFlagset(config), authEntryPoint)
	return err
}

func storeConfigValue(invocationCtx workflow.InvocationContext, key string, value string) error {
	config := configuration.New()
	config.Set(configuration.RAW_CMD_ARGS, []string{"config", "set", key + "=" + value})
	config.Set(configuration.WORKFLOW_USE_STDIO, false)
	_, legacyCLIError := invocationCtx.GetEngine().InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
	return legacyCLIError
}

func storeToken(invocationCtx workflow.InvocationContext, token *oauth2.Token) {
	_ = storeConfigValue(invocationCtx, "SNYK_OAUTH_TOKEN", token.AccessToken)
	_ = storeConfigValue(invocationCtx, "SNYK_OAUTH_TOKEN_EXPIRES", fmt.Sprintf("%d", token.Expiry.Unix()))
	if len(token.RefreshToken) > 0 {
		_ = storeConfigValue(invocationCtx, "SNYK_OAUTH_TOKEN_REFRESH", token.RefreshToken)
	}
}

// authEntryPoint is the entry point for the auth workflow.
func authEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetLogger()
	engine := invocationCtx.GetEngine()

	output = []workflow.Data{} // always empty
	oauthEnabled := config.GetBool(oauthFlag)

	logger.Println("OAuth enabled:", oauthEnabled)

	if oauthEnabled { // OAUTH flow
		headless := config.GetBool(headlessFlag)
		logger.Println("Headless:", headless)

		httpClient := invocationCtx.GetNetworkAccess().GetHttpClient()
		token, authError := auth.Authenticate(httpClient, headless)
		if authError != nil {
			return output, authError
		}

		logger.Println("Oauth token expires:", token.Expiry)

		// TODO: https://snyksec.atlassian.net/browse/HEAD-58
		fmt.Println("Successfully authenticated!")

		// TODO use configuration to store
		storeToken(invocationCtx, token)

	} else { // LEGACY flow
		config.Set(configuration.RAW_CMD_ARGS, os.Args[1:])
		config.Set(configuration.WORKFLOW_USE_STDIO, true)
		_, legacyCLIError := engine.InvokeWithConfig(workflow.NewWorkflowIdentifier("legacycli"), config)
		if legacyCLIError != nil {
			return output, legacyCLIError
		}
	}

	return output, err
}
