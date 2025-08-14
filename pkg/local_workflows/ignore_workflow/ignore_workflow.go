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
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/spf13/pflag"

	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/error-catalog-golang-public/cli"

	policyApi "github.com/snyk/go-application-framework/internal/api/policy/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/utils/git"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	ignoreCreateWorkflowName = "ignore.create"
	ignoreEditWorkflowName   = "ignore.edit"
	ignoreDeleteWorkflowName = "ignore.delete"

	FindingsIdKey         = "finding-id"
	findingsIdPromptHelp  = "\nEnter the Finding ID of the issue you want to ignore."
	findingsIdDescription = "Finding ID"

	IgnoreIdKey         = "ignore-id"
	IgnoreIdDescription = "Ignore ID"

	IgnoreTypeKey         = "ignore-type"
	ignoreTypePromptHelp  = "\nEnter the ignore type: [not-vulnerable, wont-fix, temporary-ignore]."
	ignoreTypeDescription = "Ignore Type"

	ReasonKey         = "reason"
	reasonPromptHelp  = "\nProvide a reason for why this issue is ignored."
	reasonDescription = "Reason"

	ExpirationKey         = "expiration"
	expirationPromptHelp  = "\nEnter the expiration date in YYYY-MM-DD format or leave empty for no expiration."
	expirationDescription = "Expiration"

	RemoteRepoUrlKey         = configuration.FLAG_REMOTE_REPO_URL
	remoteRepoUrlPromptHelp  = "\nProvide the remote repository URL."
	remoteRepoUrlDescription = "Remote Repository URL"

	InteractiveKey    = "interactive"
	EnrichResponseKey = "enrich_response"

	policyAPIVersion = "2024-10-15"
	policyApiTimeout = time.Minute

	interactiveEnsureVersionControlMessage    = "👉🏼 Ensure the code containing the issue is committed and pushed to remote origin, so approvers can review it."
	interactiveIgnoreRequestSubmissionMessage = "✅ Your ignore request has been submitted."

	ConfigIgnoreApprovalEnabled = "internal_iaw_enabled"
)

var reasonPromptHelpMap = map[string]string{
	string(policyApi.WontFix):         "\nProvide a reason for why this issue won't be fixed.",
	string(policyApi.TemporaryIgnore): "\nProvide a reason for why this issue is temporarily ignored.",
	string(policyApi.NotVulnerable):   "\nProvide a reason for why this issue is not vulnerable.",
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

	engine.GetConfiguration().AddDefaultValue(ConfigIgnoreApprovalEnabled, getOrgIgnoreApprovalEnabled(engine))

	return nil
}

//nolint:gocyclo // to avoid repetition it's easier to read this way
func ignoreCreateWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	logger := invocationCtx.GetEnhancedLogger()
	userInterface := invocationCtx.GetUserInterface()
	config := invocationCtx.GetConfiguration()
	id := invocationCtx.GetWorkflowIdentifier()

	enabled, enabledError := config.GetBoolWithError(ConfigIgnoreApprovalEnabled)
	if enabledError != nil {
		return nil, enabledError
	}

	if !enabled {
		orgName := config.GetString(configuration.ORGANIZATION_SLUG)
		appUrl := config.GetString(configuration.WEB_APP_URL)
		settingsUrl := fmt.Sprintf("%s/org/%s/manage/settings", appUrl, orgName)
		disabledError := cli.NewFeatureNotEnabledError(fmt.Sprintf(`Ignore Approval Workflow is disabled for "%s".`, orgName), snyk_errors.WithLinks([]string{settingsUrl}))
		return nil, disabledError
	}

	interactive := config.GetBool(InteractiveKey)
	addCreateIgnoreDefaultConfigurationValues(invocationCtx)

	if interactive {
		uiErr := userInterface.Output("\n" + interactiveEnsureVersionControlMessage)
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

	expireStr, err := config.GetStringWithError(ExpirationKey)
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

		expireStr, err = promptIfEmpty(expireStr, userInterface, expirationPromptHelp, expirationDescription, isValidInteractiveExpiration)
		if err != nil {
			return nil, err
		}
		// an empty expiration means the ignores never expires
		if expireStr == "" {
			expireStr = local_models.DefaultSuppressionExpiration
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

		uiErr := userInterface.Output(getIgnoreRequestDetailsStructure(expireStr, userName, orgName, ignoreType, reason))
		if uiErr != nil {
			logger.Warn().Err(err).Send()
		}
	} else {
		if findingsId == "" {
			return nil, cli.NewEmptyFlagOptionError("The finding-id is required. Provide it using the --finding-id flag.")
		}

		if ignoreType == "" {
			return nil, cli.NewEmptyFlagOptionError("The ignore-type is required cannot be empty. Provide it using the --ignore-type flag. Valid values are: not-vulnerable, wont-fix, temporary-ignore.")
		}

		if expireStr == "" {
			return nil, cli.NewEmptyFlagOptionError("The expiration flag is required and cannot be empty. Provide it using the --expiration flag. The date format is YYYY-MM-DD or 'never' for no expiration.")
		}

		if reason == "" {
			return nil, cli.NewEmptyFlagOptionError("The reason flag is required and cannot be empty. Provide it using the --reason flag.")
		}

		if repoUrl == "" {
			return nil, cli.NewEmptyFlagOptionError("The remote repository URL could not be automatically detected. Provide it using the --remote-repo-url flag.")
		}
	}

	branchName, branchNameErr := git.BranchNameFromDir(config.GetString(configuration.INPUT_DIRECTORY))
	if branchNameErr != nil {
		logger.Warn().Err(err).Send()
	}

	expire, err := getExpireValue(expireStr)
	if err != nil {
		return nil, err
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

func getIgnoreRequestDetailsStructure(expire, userName, orgName, ignoreType, reason string) string {
	requestedOn := time.Now().Format(time.DateOnly)
	return fmt.Sprintf("\n  Organization:  %s\n  Requested on:  %s\n  Requested by:  %s\n  Expiration:    %s\n  Ignore type:   %s\n  Reason:        %s", orgName, requestedOn, userName, expire, ignoreType, reason)
}

func getExpireValue(expiryString string) (*time.Time, error) {
	if expiryString == local_models.DefaultSuppressionExpiration {
		//nolint:nilnil // we are returning a pointer or an error, in this case the nil pointer means the ignore never expires
		return nil, nil
	}

	expireVal, parseErr := time.Parse(time.DateOnly, expiryString)
	if parseErr != nil {
		return nil, parseErr
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
