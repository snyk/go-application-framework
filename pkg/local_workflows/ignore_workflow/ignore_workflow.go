package ignore_workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/spf13/pflag"

	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/error-catalog-golang-public/cli"

	policyApi "github.com/snyk/go-application-framework/internal/api/policy/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/utils/git"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ignoreCreateWorkflowName = "ignore.create"
	ignoreEditWorkflowName   = "ignore.edit"
	ignoreDeleteWorkflowName = "ignore.delete"

	FindingsIdKey         = "finding-id"
	findingsIdPromptHelp  = "Enter the Finding ID of the issue you want to ignore."
	findingsIdDescription = "Finding ID"

	IgnoreIdKey         = "ignore-id"
	IgnoreIdDescription = "Ignore ID"

	IgnoreTypeKey         = "ignore-type"
	ignoreTypePromptHelp  = "Enter the ignore type: [not-vulnerable, wont-fix, temporary-ignore]."
	ignoreTypeDescription = "Ignore Type"

	ReasonKey         = "reason"
	reasonPromptHelp  = "Provide a reason for why this ignore was created."
	reasonDescription = "Reason"

	ExpirationKey         = "expiry"
	expirationDescription = "Expiration (YYYY-MM-DD)"

	RemoteRepoUrlKey         = configuration.FLAG_REMOTE_REPO_URL
	remoteRepoUrlPromptHelp  = "Provide the remote repository URL."
	remoteRepoUrlDescription = "Remote Repository URL"

	InteractiveKey    = "interactive"
	EnrichResponseKey = "enrich_response"

	policyAPIVersion = "2024-10-15"
	policyApiTimeout = time.Minute

	interactiveEnsureVersionControlMessage    = "👉🏼 Ensure the code containing the issue is committed and pushed to remote origin, so approvers can review it."
	interactiveIgnoreRequestSubmissionMessage = "✅ Your ignore request has been submitted."
)

var reasonPromptHelpMap = map[string]string{
	string(policyApi.WontFix):         "Provide a reason for why this issue won't be fixed.",
	string(policyApi.TemporaryIgnore): "Provide a reason for why this issue is temporarily ignored.",
	string(policyApi.NotVulnerable):   "Provide a reason for why this issue is not vulnerable.",
}

var WORKFLOWID_IGNORE_CREATE workflow.Identifier = workflow.NewWorkflowIdentifier(ignoreCreateWorkflowName)
var WORKFLOWID_IGNORE_EDIT workflow.Identifier = workflow.NewWorkflowIdentifier(ignoreEditWorkflowName)
var WORKFLOWID_IGNORE_DELETE workflow.Identifier = workflow.NewWorkflowIdentifier(ignoreDeleteWorkflowName)

func InitIgnoreWorkflows(engine workflow.Engine) error {
	createFlagset := pflag.NewFlagSet(ignoreCreateWorkflowName, pflag.ExitOnError)
	createFlagset.String(FindingsIdKey, "", findingsIdDescription)
	createFlagset.String(IgnoreTypeKey, "", ignoreTypeDescription)
	createFlagset.String(ReasonKey, "", reasonDescription)
	createFlagset.String(ExpirationKey, "", expirationDescription)
	createFlagset.String(RemoteRepoUrlKey, "", remoteRepoUrlDescription)
	// If set to false, no response will be returned
	createFlagset.Bool(EnrichResponseKey, false, "")
	createFlagset.Bool(InteractiveKey, true, "")

	_, err := engine.Register(WORKFLOWID_IGNORE_CREATE, workflow.ConfigurationOptionsFromFlagset(createFlagset), ignoreCreateWorkflowEntryPoint)
	if err != nil {
		return err
	}

	config_utils.AddFeatureFlagToConfig(engine, configuration.FF_IAW_ENABLED, "ignoreApprovalWorkflow")

	return nil
}

//nolint:gocyclo // to avoid repetition it's easier to read this way
func ignoreCreateWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	logger := invocationCtx.GetEnhancedLogger()
	userInterface := invocationCtx.GetUserInterface()
	config := invocationCtx.GetConfiguration()
	id := invocationCtx.GetWorkflowIdentifier()

	if !config.GetBool(configuration.FF_IAW_ENABLED) {
		return nil, cli.NewFeatureUnderDevelopmentError("")
	}

	interactive := config.GetBool(InteractiveKey)
	addCreateIgnoreDefaultConfigurationValues(invocationCtx)

	if interactive {
		uiErr := userInterface.Output("\n" + interactiveEnsureVersionControlMessage + "\n")
		if uiErr != nil {
			logger.Warn().Err(err).Send()
		}
	}

	userName, err := getUser(invocationCtx)
	if err != nil {
		return nil, err
	}

	findingsId, err := config.GetStringWithError(FindingsIdKey)
	if err != nil {
		return nil, err
	}

	ignoreType, err := config.GetStringWithError(IgnoreTypeKey)
	if err != nil {
		return nil, err
	}

	repoUrl, err := config.GetStringWithError(RemoteRepoUrlKey)
	if err != nil {
		return nil, err
	}

	// read expiry time
	// if expiration value is empty it will be treated as no-expire by the policy endpoint
	expire, err := getExpireValue(config)
	if err != nil {
		return nil, err
	}

	reason, err := config.GetStringWithError(ReasonKey)
	if err != nil {
		return nil, err
	}

	orgUuid, err := uuid.Parse(config.GetString(configuration.ORGANIZATION))
	if err != nil {
		return nil, err
	}

	if interactive {
		findingsId, err = promptIfEmpty(findingsId, userInterface, findingsIdPromptHelp, findingsIdDescription, isValidFindingsId)
		if err != nil {
			return nil, err
		}

		ignoreType, err = promptIfEmpty(ignoreType, userInterface, ignoreTypePromptHelp, ignoreTypeDescription, isValidIgnoreType)
		if err != nil {
			return nil, err
		}

		reasonHelp, ok := reasonPromptHelpMap[ignoreType]
		if !ok {
			reasonHelp = reasonPromptHelp
		}
		reason, err = promptIfEmpty(reason, userInterface, reasonHelp, reasonDescription, isValidReason)
		if err != nil {
			return nil, err
		}

		repoUrl, err = promptIfEmpty(repoUrl, userInterface, remoteRepoUrlPromptHelp, remoteRepoUrlDescription, isValidRepoUrl)
		if err != nil {
			return nil, err
		}

		orgName := config.GetString(configuration.ORGANIZATION_SLUG)

		uiErr := userInterface.Output(getIgnoreRequestDetailsStructure(expire, userName, orgName, ignoreType, reason))
		if uiErr != nil {
			logger.Warn().Err(err).Send()
		}
	}

	branchName, branchNameErr := git.BranchNameFromDir(config.GetString(configuration.INPUT_DIRECTORY))
	if branchNameErr != nil {
		logger.Warn().Err(err).Send()
	}

	payload := createPayload(repoUrl, branchName, expire, ignoreType, reason, findingsId)
	response, err := sendCreateIgnore(invocationCtx, payload, orgUuid)

	if err != nil {
		return nil, err
	}

	if interactive {
		uiErr := userInterface.Output("\n  " + interactiveIgnoreRequestSubmissionMessage + "\n")
		if uiErr != nil {
			logger.Warn().Err(err).Send()
		}
	}

	if config.GetBool(EnrichResponseKey) {
		data, workflowDataErr := createIgnoreWorkflowData(
			workflow.NewTypeIdentifier(id, ignoreCreateWorkflowName),
			config,
			policyResponseToSarifSuppression(response),
			logger)
		if workflowDataErr != nil {
			return nil, workflowDataErr
		}
		output = append(output, data)
	}

	return output, err
}

func getIgnoreRequestDetailsStructure(expire *time.Time, userName, orgName, ignoreType, reason string) string {
	requestedOn := time.Now().Format(time.DateOnly)
	expireDisplayText := local_models.DefaultSuppressionExpiry
	if expire != nil {
		expireDisplayText = expire.Format(time.DateOnly)
	}
	return fmt.Sprintf("  Requested on:  %s\n  Requested by:  %s\n  Organization:  %s\n  Expiration:    %s\n  Ignore type:   %s\n  Reason:        %s", requestedOn, userName, orgName, expireDisplayText, ignoreType, reason)
}

func getExpireValue(config configuration.Configuration) (*time.Time, error) {
	shouldParse := config.IsSet(ExpirationKey) || config.GetBool(InteractiveKey)
	if !shouldParse {
		//nolint:nilnil // returning nil,nil here means that there is no expiration, and we didn't run into an error which is a valid case
		return nil, nil
	}
	expireStr, err := config.GetStringWithError(ExpirationKey)
	if err != nil || expireStr == "" {
		return nil, err
	}

	expireVal, parseErr := time.Parse(time.DateOnly, expireStr)
	if parseErr != nil {
		return nil, err
	}

	return &expireVal, nil
}

func createIgnoreWorkflowData(id workflow.Identifier, config configuration.Configuration, ignoreResponse *sarif.Suppression, logger *zerolog.Logger) (workflow.Data, error) {
	if ignoreResponse == nil {
		return nil, fmt.Errorf("ignore response is nil")
	}
	marshalledObj, err := json.Marshal(ignoreResponse)
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

func createPayload(repoUrl string, branchName string, expire *time.Time, ignoreType string, reason string, findingsId string) policyApi.CreatePolicyPayload {
	meta := policyApi.Meta{}
	meta["repo_url"] = repoUrl
	meta["branch_name"] = branchName

	var payload policyApi.CreateOrgPolicyApplicationVndAPIPlusJSONRequestBody
	payload.Data.Meta = &meta
	payload.Data.Attributes.Action.Data = policyApi.PolicyActionIgnoreData{
		Expires:    expire,
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

func getUser(invocationCtx workflow.InvocationContext) (string, error) {
	config := invocationCtx.GetConfiguration().Clone()
	config.Set(configuration.FLAG_EXPERIMENTAL, true)

	data, err := invocationCtx.GetEngine().InvokeWithConfig(localworkflows.WORKFLOWID_WHOAMI, config)
	if err != nil {
		return "", err
	}

	if len(data) > 0 {
		user, ok := data[0].GetPayload().(string)
		if !ok {
			return "", fmt.Errorf("payload is not a string")
		}
		return user, nil
	} else {
		return "", fmt.Errorf("no payload found")
	}
}

func sendCreateIgnore(invocationCtx workflow.InvocationContext, input policyApi.CreateOrgPolicyApplicationVndAPIPlusJSONRequestBody, orgUuid uuid.UUID) (*policyApi.PolicyResponse, error) {
	config := invocationCtx.GetConfiguration()
	host, err := url.JoinPath(config.GetString(configuration.API_URL), "rest")
	if err != nil {
		return nil, err
	}

	params := policyApi.CreateOrgPolicyParams{Version: policyAPIVersion}

	client, err := policyApi.NewClient(host, policyApi.WithHTTPClient(invocationCtx.GetNetworkAccess().GetHttpClient()))
	if err != nil {
		return nil, err
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), policyApiTimeout)
	defer cancelFunc()

	resp, err := client.CreateOrgPolicyWithApplicationVndAPIPlusJSONBody(ctx, orgUuid, &params, input)
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			err = closeErr
		}
	}()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("error sending request: Status %s StatusCode %d", resp.Status, resp.StatusCode)
	}

	parsedResponse, err := policyApi.ParseCreateOrgPolicyResponse(resp)

	if err != nil {
		return nil, err
	}
	if parsedResponse.ApplicationvndApiJSON201 == nil {
		return nil, fmt.Errorf("error unmarshalling CreateOrgPolicyResponse response")
	}
	return &parsedResponse.ApplicationvndApiJSON201.Data, err
}
