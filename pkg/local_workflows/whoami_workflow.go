package localworkflows

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

const (
	workflowName     = "whoami"
	mimeTypeJSON     = "application/json"
	endpoint         = "user/me"
	experimentalFlag = "experimental"
)

var WORKFLOWID_WHOAMI workflow.Identifier = workflow.NewWorkflowIdentifier(workflowName)

func InitWhoAmIWorkflow(engine workflow.Engine) error {
	// initialise workflow configuration
	whoAmIConfig := pflag.NewFlagSet(workflowName, pflag.ExitOnError)
	whoAmIConfig.Bool(experimentalFlag, false, "enable experimental whoAmI command")

	// register workflow with engine
	_, err := engine.Register(WORKFLOWID_WHOAMI, workflow.ConfigurationOptionsFromFlagset(whoAmIConfig), whoAmIWorkflowEntryPoint)
	return err
}

func whoAmIWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetLogger()
	httpClient := invocationCtx.GetNetworkAccess().GetHttpClient()

	logger.Println("whoAmI workflow start")

	// only run if experimental flag is set
	if !config.GetBool(experimentalFlag) {
		return nil, fmt.Errorf("set `--experimental` flag to enable whoAmI command")
	}

	// define userme API endpoint
	baseUrl := config.GetString(configuration.API_URL)
	url := baseUrl + endpoint

	// call userme API endpoint
	whoAmI, err := fetchWhoAmI(httpClient, url, logger)

	// parse response
	whoAmIData := workflow.NewData(WORKFLOWID_WHOAMI, mimeTypeJSON, whoAmI)

	// return userme data
	return []workflow.Data{whoAmIData}, err
}

func fetchWhoAmI(client *http.Client, endpoint string, logger *log.Logger) (whoAmI []byte, err error) {
	logger.Printf("Fetching user details (url: %s)", endpoint)
	res, err := client.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("error while making request: %w", err)
	}

	if res.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("invalid API key (status %s)", res.Status)
	} else if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed (status %s)", res.Status)
	}

	defer res.Body.Close()
	whoAmI, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error while reading response body: %w", err)
	}
	logger.Println("Successfully fetched user details")

	return whoAmI, nil
}
