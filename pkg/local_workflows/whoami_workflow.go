package localworkflows

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/snyk/go-application-framework/internal/api/contract"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/spf13/pflag"
)

const (
	workflowName     = "whoami"
	mimeTypeJSON     = "application/json"
	endpoint         = "/user/me"
	apiVersion       = "/v1"
	experimentalFlag = "experimental"
	jsonFlag         = "json"
)

// define a new workflow identifier for this workflow
var WORKFLOWID_WHOAMI workflow.Identifier = workflow.NewWorkflowIdentifier(workflowName)

func InitWhoAmIWorkflow(engine workflow.Engine) error {
	// initialise workflow configuration
	whoAmIConfig := pflag.NewFlagSet(workflowName, pflag.ExitOnError)
	// add experimental flag to configuration
	whoAmIConfig.Bool(experimentalFlag, false, "enable experimental whoAmI command")
	// add json flag to configuration
	whoAmIConfig.Bool(jsonFlag, false, "output in json format")

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
	url := baseUrl + apiVersion + endpoint

	// call userme API endpoint
	userMe, err := fetchUserMe(httpClient, url, logger)
	if err != nil {
		return nil, fmt.Errorf("error while fetching user: %w", err)
	}

	// extract user from response
	user, err := extractUser(userMe, logger)
	if err != nil {
		return nil, fmt.Errorf("error while extracting user: %w", err)
	}

	// return full payload if json flag is set
	if config.GetBool(jsonFlag) {
		// parse response
		userMeData := createWorkflowData(userMe)

		// return userme data
		return []workflow.Data{userMeData}, err
	}

	userData := createWorkflowData(user)
	return []workflow.Data{userData}, err
}

func fetchUserMe(client *http.Client, url string, logger *log.Logger) (whoAmI []byte, err error) {
	logger.Printf("Fetching user details (url: %s)", url)
	res, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("error while making request: %w", err)
	}

	if res.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("invalid API key (status %d)", res.StatusCode)
	} else if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("request failed (status %d)", res.StatusCode)
	}

	defer res.Body.Close()
	whoAmI, err = io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error while reading response body: %w", err)
	}
	logger.Println("Successfully fetched user details")

	return whoAmI, nil
}

func extractUser(whoAmI []byte, logger *log.Logger) (username string, err error) {
	logger.Println("Extracting user from response")

	// parse userme response
	var userMe contract.UserMe
	err = json.Unmarshal(whoAmI, &userMe)
	if err != nil {
		return "", fmt.Errorf("error while parsing response: %w", err)
	}
	logger.Printf("Successfully parsed response (user: %+v)", userMe)

	// check if userme.UserName is nil
	if userMe.UserName == nil {
		return "", fmt.Errorf("missing property 'username'")
	}

	// extract user from response
	username = *userMe.UserName
	logger.Printf("Successfully extracted user from response (user: %s)", username)
	return username, nil
}

func createWorkflowData(data interface{}) workflow.Data {
	// use new type identifier when creating new data
	return workflow.NewData(
		workflow.NewTypeIdentifier(WORKFLOWID_WHOAMI, workflowName),
		mimeTypeJSON,
		data,
	)
}
