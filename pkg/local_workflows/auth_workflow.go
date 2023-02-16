package localworkflows

import (
	"os"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

const (
	workflowNameAuth = "auth"
	oauthFlag        = "oauth"
	endpointAuth     = "/user/me"
	apiVersionAuth   = "/v1"
)

// define a new workflow identifier for this workflow
var WORKFLOWID_AUTH workflow.Identifier = workflow.NewWorkflowIdentifier(workflowNameAuth)

// InitAuth initialises the auth workflow before registering it with the engine.
func InitAuth(engine workflow.Engine) error {
	config := pflag.NewFlagSet(workflowNameAuth, pflag.ExitOnError)
	config.Bool(oauthFlag, false, "Enable OAuth authentication")

	_, err := engine.Register(WORKFLOWID_AUTH, workflow.ConfigurationOptionsFromFlagset(config), authEntryPoint)
	return err
}

// authEntryPoint is the entry point for the auth workflow.
func authEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetLogger()
	engine := invocationCtx.GetEngine()
	//httpClient := invocationCtx.GetNetworkAccess().GetHttpClient()

	output = []workflow.Data{} // always empty
	oauthEnabled := config.GetBool(oauthFlag)

	logger.Println("OAuth enabled:", oauthEnabled)

	if oauthEnabled { // OAUTH flow

		// define userme API endpointAuth
		// baseUrl := config.GetString(configuration.API_URL)
		// url := baseUrl + apiVersionAuth + endpointAuth

		auth.Authenticate(config)

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
