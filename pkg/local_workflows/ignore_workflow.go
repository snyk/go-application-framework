package localworkflows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/pflag"

	policyApi "github.com/snyk/go-application-framework/internal/api/policy/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
	"github.com/snyk/go-application-framework/pkg/utils/git"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ignoreCreateWorkflowName = "ignore.create"
	ignoreEditWorkflowName   = "ignore.edit"
	ignoreDeletWorkflowName  = "ignore.delete"

	findingsIdKey         = "id"
	findingsIdDescription = "Findings Id"

	ignoreIdKey         = "ignore-id"
	ignoreIdDescription = "Ignore Id"

	ignoreTypeKey         = "ignore-type"
	ignoreTypeDescription = "Ignore Type"

	reasonKey         = "reason"
	reasonDescription = "Reason"

	expirationKey         = "expires"
	expirationDescription = "Expiration (YYYY-MM-DD)"

	remoteRepoUrlKey         = code_workflow.ConfigurationRemoteRepoUrlFlagname
	remoteRepoUrlDescription = "Remote Repository URL"

	interactiveKey    = "interactive"
	enrichResponseKey = "enrich_response"

	policyAPIVersion = "2024-10-15"
)

// TODOS:
// Add ignore enum check
// Add httpclient and somehow call it

var WORKFLOWID_IGNORE_CREATE workflow.Identifier = workflow.NewWorkflowIdentifier(ignoreCreateWorkflowName)
var WORKFLOWID_IGNORE_EDIT workflow.Identifier = workflow.NewWorkflowIdentifier(ignoreEditWorkflowName)
var WORKFLOWID_IGNORE_DELETE workflow.Identifier = workflow.NewWorkflowIdentifier(ignoreDeletWorkflowName)

func InitIgnoreWorkflows(engine workflow.Engine) error {
	createFlagset := pflag.NewFlagSet(ignoreCreateWorkflowName, pflag.ExitOnError)
	createFlagset.String(findingsIdKey, "", findingsIdDescription)
	createFlagset.String(ignoreTypeKey, "", ignoreTypeDescription)
	createFlagset.String(reasonKey, "", reasonDescription)
	createFlagset.String(expirationKey, "", expirationDescription)
	createFlagset.String(remoteRepoUrlKey, "", remoteRepoUrlDescription)
	// If set to false, no response will be returned
	createFlagset.Bool(enrichResponseKey, false, "")
	createFlagset.Bool(interactiveKey, true, "")
	_, err := engine.Register(WORKFLOWID_IGNORE_CREATE, workflow.ConfigurationOptionsFromFlagset(createFlagset), ignoreCreateWorkflowEntryPoint)

	editFlagset := pflag.NewFlagSet(ignoreEditWorkflowName, pflag.ExitOnError)
	editFlagset.String(ignoreIdKey, "", ignoreIdDescription)
	editFlagset.String(findingsIdKey, "", findingsIdDescription)
	editFlagset.String(ignoreTypeKey, "", ignoreTypeDescription)
	editFlagset.String(reasonKey, "", reasonDescription)
	editFlagset.String(expirationKey, "", expirationDescription)
	editFlagset.String(remoteRepoUrlKey, "", remoteRepoUrlDescription)
	// If set to false, no response will be returned
	editFlagset.Bool(enrichResponseKey, false, "")
	editFlagset.Bool(interactiveKey, true, "")
	_, err = engine.Register(WORKFLOWID_IGNORE_EDIT, workflow.ConfigurationOptionsFromFlagset(editFlagset), ignoreEditWorkflowEntryPoint)

	deleteFlagSet := pflag.NewFlagSet(ignoreDeletWorkflowName, pflag.ExitOnError)
	deleteFlagSet.String(ignoreIdKey, "", ignoreIdDescription)
	// If set to false, no response will be returned
	deleteFlagSet.Bool(enrichResponseKey, false, "")
	deleteFlagSet.Bool(interactiveKey, true, "")
	_, err = engine.Register(WORKFLOWID_IGNORE_DELETE, workflow.ConfigurationOptionsFromFlagset(deleteFlagSet), ignoreDeleteWorkflowEntryPoint)

	return err
}

func getIgnoreRequestDetailsStructure(expire time.Time, userName string, ignoreType string) string {
	expireDisplayText := "Does not expire"
	if !expire.IsZero() {
		expireDisplayText = expire.Format(time.DateOnly)
	}
	return fmt.Sprintf("  Requested on:  2024-08-10\n  Requested by:  %s\n  Expiration:    %s\n  Ignore type:   %s", userName, expireDisplayText, ignoreType)
}

func ignoreEditWorkflowEntryPoint(_ workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	panic("not implemented")
}
func ignoreDeleteWorkflowEntryPoint(_ workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	panic("not implemented")
}

func ignoreCreateWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	logger := invocationCtx.GetEnhancedLogger()
	userInterface := invocationCtx.GetUserInterface()
	config := invocationCtx.GetConfiguration()
	id := invocationCtx.GetWorkflowIdentifier()

	interactive := config.GetBool(interactiveKey)
	if interactive {
		// add interactive default function
		addDefaultCreateInteractiveValues(invocationCtx)
	}

	userName, err := getUserName(invocationCtx)
	if err != nil {
		return nil, fmt.Errorf("user is not authenticated: %w", err)
	}

	findingsId, err := config.GetStringWithError(findingsIdKey)
	if err != nil {
		return nil, err
	}
	_ = userInterface.Output(findingsId)

	ignoreType, err := config.GetStringWithError(ignoreTypeKey)
	if err != nil {
		return nil, err
	}
	_ = userInterface.Output(ignoreType)

	repoUrl, err := config.GetStringWithError(code_workflow.ConfigurationRemoteRepoUrlFlagname)
	if err != nil {
		return nil, err
	}
	_ = userInterface.Output(repoUrl)

	// read expiry time
	var expire time.Time
	if expireStr, getConfigErr := config.GetStringWithError(expirationKey); getConfigErr == nil {
		// TODO: if we can't parse date should it be treated as non-expire?
		expire, _ = time.Parse(time.DateOnly, expireStr)
	} else {
		return nil, getConfigErr
	}

	_ = userInterface.Output(expire.Format(time.DateOnly))

	reason, err := config.GetStringWithError(reasonKey)
	if err != nil {
		return nil, err
	}

	if interactive {
		_ = userInterface.Output("You are about to ignore the following issue:\n👉🏼 Make sure the code containing the issue is committed, and pushed to a remote origin, so the approvers are able to analyze it.\n")
		_ = userInterface.Output(getIgnoreRequestDetailsStructure(expire, userName, ignoreType))
		yesNoString, inputError := userInterface.Input("\nAdd a reason for ignoring this issue [Y/N]?")
		if inputError != nil {
			return nil, inputError
		}
		if strings.ToLower(yesNoString) != "y" && strings.ToLower(yesNoString) != "yes" {
			return nil, fmt.Errorf("operation canceled by user")
		}
	}

	url := fmt.Sprintf("%s/rest/orgs/%s/policies?version=%s", config.GetString(configuration.API_URL), config.Get(configuration.ORGANIZATION), policyAPIVersion)
	branchName, _ := git.BranchNameFromDir(config.GetString(configuration.INPUT_DIRECTORY))
	payload := createPayload(repoUrl, branchName, expire, ignoreType, reason, findingsId)
	response, err := createPolicy(invocationCtx, payload, url)

	if err != nil {
		return nil, err
	}

	logger.Printf(string(response.Attributes.Review))

	if interactive {
		_ = userInterface.Output("\nYour ignore request has been submitted for approval.")
	}

	if config.GetBool(enrichResponseKey) {
		data, workFlowDataErr := createCodeWorkflowData(
			workflow.NewTypeIdentifier(id, ignoreCreateWorkflowName),
			config,
			response,
			logger)
		if workFlowDataErr != nil {
			return nil, workFlowDataErr
		}
		output = append(output, data)
	}

	return output, err
}

func createCodeWorkflowData(id workflow.Identifier, config configuration.Configuration, obj any, logger *zerolog.Logger) (workflow.Data, error) {
	marshalledObj, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	data := workflow.NewData(
		id,
		"application/json",
		marshalledObj,
		workflow.WithConfiguration(config),
		workflow.WithLogger(logger),
	)

	return data, nil
}

func createPayload(repoUrl string, branchName string, expire time.Time, ignoreType string, reason string, findingsId string) policyApi.CreatePolicyPayload {
	meta := policyApi.Meta{}
	meta["repo_url"] = repoUrl
	meta["branch_name"] = branchName

	var payload policyApi.CreatePolicyPayload
	payload.Data.Meta = &meta
	payload.Data.Attributes.Action.Data = policyApi.PolicyActionIgnoreData{
		Expires:    &expire,
		IgnoreType: policyApi.PolicyActionIgnoreDataIgnoreType(ignoreType),
		Reason:     &reason,
	}
	payload.Data.Attributes.ActionType = policyApi.PolicyAttributesActionTypeIgnore
	payload.Data.Attributes.ConditionsGroup = policyApi.PolicyConditionsGroup{
		Conditions: []policyApi.PolicyCondition{
			{
				Field:    policyApi.Snykassetfindingv1,
				Operator: policyApi.Includes,
				Value:    findingsId,
			},
		},
		LogicalOperator: policyApi.And,
	}
	payload.Data.Type = policyApi.CreatePolicyPayloadDataTypePolicy
	return payload
}

func addDefaultCreateInteractiveValues(invocationCtx workflow.InvocationContext) {
	config := invocationCtx.GetConfiguration()
	userInterface := invocationCtx.GetUserInterface()

	config.AddDefaultValue(findingsIdKey, func(existingValue interface{}) (interface{}, error) {
		if existingValue != nil && existingValue != "" {
			return existingValue, nil
		}
		return userInterface.Input(findingsIdDescription)
	})

	config.AddDefaultValue(ignoreTypeKey, func(existingValue interface{}) (interface{}, error) {
		invalidIgnoreTypeErr := fmt.Errorf("invalid ignore type, valid ignore types are: %s, %s, %s",
			policyApi.NotVulnerable, policyApi.TemporaryIgnore, policyApi.WontFix)
		if existingValue != nil && existingValue != "" {
			if !validIgnoreType(existingValue.(string)) {
				return "", invalidIgnoreTypeErr
			}
			return existingValue, nil
		}
		ignoreType, err := userInterface.Input(ignoreTypeDescription)
		if err != nil {
			return "", err
		}
		if !validIgnoreType(ignoreType) {
			return "", invalidIgnoreTypeErr
		}
		return ignoreType, nil
	})

	config.AddDefaultValue(reasonKey, func(existingValue interface{}) (interface{}, error) {
		if existingValue != nil && existingValue != "" {
			return existingValue, nil
		}
		return userInterface.Input(reasonDescription)
	})

	config.AddDefaultValue(expirationKey, func(existingValue interface{}) (interface{}, error) {
		if existingValue != nil && existingValue != "" {
			return existingValue, nil
		}
		return userInterface.Input(expirationKey)
	})

	config.AddDefaultValue(remoteRepoUrlKey, func(existingValue interface{}) (interface{}, error) {
		if existingValue != nil && existingValue != "" {
			return existingValue, nil
		}

		getRepoUrlFromRepo := func() (string, error) {
			repoUrl, err := git.RepoUrlFromDir(config.GetString(configuration.INPUT_DIRECTORY))
			if err != nil {
				return "", err
			}
			return repoUrl, nil
		}

		repoUrl, err := getRepoUrlFromRepo()
		if err != nil {
			return userInterface.Input(remoteRepoUrlDescription)
		}

		return repoUrl, nil
	})
}

func validIgnoreType(ignoreType string) bool {
	ignoreTypeMapped := policyApi.PolicyActionIgnoreDataIgnoreType(ignoreType)
	return ignoreTypeMapped == policyApi.TemporaryIgnore || ignoreTypeMapped == policyApi.WontFix || ignoreTypeMapped == policyApi.NotVulnerable
}

func getUserName(invocationCtx workflow.InvocationContext) (string, error) {
	config := invocationCtx.GetConfiguration().Clone()
	config.Set(configuration.FLAG_EXPERIMENTAL, true)

	data, err := invocationCtx.GetEngine().InvokeWithConfig(WORKFLOWID_WHOAMI, config)
	if err != nil {
		return "", err
	}

	noAuthErr := fmt.Errorf("user is not authenticated")
	if len(data) > 0 {
		user, ok := data[0].GetPayload().(string)
		if !ok {
			return "", noAuthErr
		}
		return user, nil
	} else {
		return "", noAuthErr
	}
}

func createPolicy(invocationCtx workflow.InvocationContext, input policyApi.CreatePolicyPayload, url string) (*policyApi.PolicyResponse, error) {
	// Create a request
	requestBody, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/vnd.api+json")

	// Send the request
	resp, err := invocationCtx.GetNetworkAccess().GetHttpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var responseWrapper struct {
		Data policyApi.PolicyResponse `json:"data"`
	}

	err = json.Unmarshal(responseBody, &responseWrapper)

	if err != nil || resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("error sending request: Status %s StatusCode %d", resp.Status, resp.StatusCode)
	}

	return &responseWrapper.Data, nil
}
