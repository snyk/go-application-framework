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
)

const (
	workflowName     = "whoami"
	endpoint         = "/user/me"
	apiVersion       = "/v1"
	experimentalFlag = "experimental"
	jsonFlag         = "json"
)

// define a new workflow identifier for this workflow
var (
	WORKFLOWID_WHOAMI workflow.Identifier = WhoAmI.Identifier()

	WhoAmI = &whoAmIWorkflow{
		Workflow: &workflow.Workflow{
			Name:     "whoami",
			TypeName: "whoami",
			Visible:  true,
			Flags: workflow.Flags{
				workflow.Flag[bool]{
					Name:         experimentalFlag,
					Usage:        "enable experimental whoAmI command",
					DefaultValue: false,
				},
				workflow.Flag[bool]{
					Name:         jsonFlag,
					Usage:        "output in json format",
					DefaultValue: false,
				},
			},
		},
	}
)

// InitWhoAmIWorkflow initialises the whoAmI workflow before registering it with the engine.
// Deprecated: use `workflow.Register(WhoAmI, engine)` directly.
func InitWhoAmIWorkflow(engine workflow.Engine) error {
	return workflow.Register(WhoAmI, engine)
}

type whoAmIWorkflow struct {
	*workflow.Workflow
}

// whoAmIWorkflowEntryPoint is the entry point for the whoAmI workflow.
// it calls the `/user/me` endpoint and returns the authenticated user's username
// it can optionally return the full `/user/me` payload response if the json flag is set
func (w whoAmIWorkflow) Entrypoint(invocation workflow.InvocationContext, _ []workflow.Data) (depGraphList []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocation.GetConfiguration()
	logger := w.Logger(invocation)
	httpClient := invocation.GetNetworkAccess().GetHttpClient()

	logger.Println("start")

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
		userMeData := createWorkflowData(userMe, "application/json")

		// return userme data
		return []workflow.Data{userMeData}, err
	}

	userData := createWorkflowData(user, "text/plain")
	return []workflow.Data{userData}, err
}

// fetchUserMe calls the `/user/me` endpoint and returns the response body
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

// extractUser extracts the username from the api response
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

// createWorkflowData creates a new workflow.Data object
func createWorkflowData(data interface{}, contentType string) workflow.Data {
	return workflow.NewData(
		// use new type identifier when creating new data
		workflow.NewTypeIdentifier(WORKFLOWID_WHOAMI, workflowName),
		contentType,
		data,
	)
}
