package localworkflows

import (
	"encoding/json"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/internal/api/contract"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

const (
	whoAmIworkflowName = "whoami"
	experimentalFlag   = configuration.FLAG_EXPERIMENTAL
	jsonFlag           = "json"
)

// define a new workflow identifier for this workflow
var WORKFLOWID_WHOAMI workflow.Identifier = workflow.NewWorkflowIdentifier(whoAmIworkflowName)

// InitWhoAmIWorkflow initializes the whoAmI workflow before registering it with the engine.
func InitWhoAmIWorkflow(engine workflow.Engine) error {
	// initialize workflow configuration
	whoAmIConfig := pflag.NewFlagSet(whoAmIworkflowName, pflag.ExitOnError)
	// add experimental flag to configuration
	whoAmIConfig.Bool(experimentalFlag, false, "enable experimental whoAmI command")
	// add json flag to configuration
	whoAmIConfig.Bool(jsonFlag, false, "output in json format")

	// register workflow with engine
	_, err := engine.Register(WORKFLOWID_WHOAMI, workflow.ConfigurationOptionsFromFlagset(whoAmIConfig), whoAmIWorkflowEntryPoint)
	return err
}

// whoAmIWorkflowEntryPoint is the entry point for the whoAmI workflow.
// it calls the `/user/me` userMeEndpoint and returns the authenticated user's username
// it can optionally return the full `/user/me` payload response if the json flag is set
func whoAmIWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	httpClient := invocationCtx.GetNetworkAccess().GetHttpClient()
	url := config.GetString(configuration.API_URL)
	var a = api.NewApi(url, httpClient)

	logger.Println("whoAmI workflow start")

	// only run if experimental flag is set
	if !config.GetBool(experimentalFlag) {
		return nil, fmt.Errorf("set `--experimental` flag to enable whoAmI command")
	}

	userMe, err := a.GetUserMe()
	if err != nil {
		return nil, fmt.Errorf("error fetching user data: %w", err)
	}

	// return full payload if json flag is set
	if config.GetBool(jsonFlag) {
		selfRes, err := a.GetSelf()
		if err != nil {
			return nil, fmt.Errorf("error fetching user data: %w", err)
		}

		userMeJSON := contract.UserMe{
			Id:       &selfRes.Data.Id,
			UserName: &selfRes.Data.Attributes.Username,
			Email:    &selfRes.Data.Attributes.Email,
			Name:     &selfRes.Data.Attributes.Name,
		}

		// parse response
		userMeJSONBytes, err := json.Marshal(userMeJSON)
		userMeData := createWorkflowData(userMeJSONBytes, "application/json", logger)

		// return userme data
		return []workflow.Data{userMeData}, err
	}

	userData := createWorkflowData(userMe, "text/plain", logger)
	return []workflow.Data{userData}, nil
}

// createWorkflowData creates a new workflow.Data object
func createWorkflowData(data interface{}, contentType string, logger *zerolog.Logger) workflow.Data {
	return workflow.NewData(
		// use new type identifier when creating new data
		workflow.NewTypeIdentifier(WORKFLOWID_WHOAMI, whoAmIworkflowName),
		contentType,
		data,
		workflow.WithLogger(logger),
	)
}
