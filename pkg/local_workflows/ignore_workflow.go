package localworkflows

import (
	"github.com/go-git/go-git/v5"
	"github.com/spf13/pflag"

	"fmt"
	"strings"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/code_workflow"
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
)

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
	editFlagset.String(ignoreIdKey, "", ignoreIdDescription)
	// If set to false, no response will be returned
	deleteFlagSet.Bool(enrichResponseKey, false, "")
	deleteFlagSet.Bool(interactiveKey, true, "")
	_, err = engine.Register(WORKFLOWID_IGNORE_DELETE, workflow.ConfigurationOptionsFromFlagset(deleteFlagSet), ignoreDeleteWorkflowEntryPoint)

	return err
}

func getIgnoreRequestDetailsStructure(expire time.Time, userName string) string {
	expireDisplayText := "Does not expire"
	if !expire.IsZero() {
		expireDisplayText = expire.Format(time.DateOnly)

	}
	return fmt.Sprintf("  Requested on:  2024-08-10\n  Requested by:  %s\n  Expiration:    %s\n  Ignore type:   false-positive", userName, expireDisplayText)
}

func sendRequest() {

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
	interactive := config.GetBool(interactiveKey)

	if interactive {
		// add interactive default function
		addDefaultCreateInteractiveValues(invocationCtx)
	}

	repoUrl, err := config.GetWithError(code_workflow.ConfigurationRemoteRepoUrlFlagname)
	if err != nil {
		return nil, err
	}

	_ = userInterface.Output(repoUrl)

	// get user
	config.Set(configuration.FLAG_EXPERIMENTAL, true)

	userName, err := getUserName(invocationCtx)
	if err != nil {
		return nil, err
	}

	// read expiry time
	var expire time.Time
	if config.IsSet(expirationKey) {
		expire, err = time.Parse(time.DateOnly, config.GetString(expirationKey))
		if err != nil {
			return output, err
		}
	}

	if interactive {
		_ = userInterface.Output("You are about to ignore the following issue:\n👉🏼 Make sure the code containing the issue is committed, and pushed to a remote origin, so the approvers are able to analyze it.\n")
		_ = userInterface.Output(getIgnoreRequestDetailsStructure(expire, userName))
	}

	reason := ""
	if !config.IsSet(reasonKey) && config.GetBool(enterReasonKey) {
		reason = config.GetString(reasonKey)
	}

	logger.Printf("Reason: %s\n", reason)
	logger.Printf("Expires: %s\n", expire)

	sendRequest()

	if interactive {
		_ = userInterface.Output("\nYour ignore request has been submitted for approval.")
	}

	return output, err
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
		if existingValue != nil && existingValue != "" {
			return existingValue, nil
		}
		return userInterface.Input(ignoreTypeDescription)
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
			repo, err := git.PlainOpenWithOptions(config.GetString(configuration.INPUT_DIRECTORY), &git.PlainOpenOptions{
				DetectDotGit: true,
			})

			if err != nil {
				return "", err
			}

			remote, err := repo.Remote("origin")
			if err != nil {
				return "", err
			}

			// based on the docs, the first URL is being used to fetch, so this is the one we use
			remoteConfig := remote.Config()
			if remoteConfig == nil || len(remoteConfig.URLs) == 0 || remoteConfig.URLs[0] == "" {
				return "", fmt.Errorf("no remote url found")
			}
			repoUrl := remoteConfig.URLs[0]
			return repoUrl, nil
		}

		repoUrl, err := getRepoUrlFromRepo()
		if err != nil {
			return userInterface.Input(remoteRepoUrlDescription)
		}

		return repoUrl, nil
	})

	config.AddDefaultValue(reasonKey, func(existingValue interface{}) (interface{}, error) {
		if existingValue != nil && existingValue != "" {
			return existingValue, nil
		}
		yesNoString, inputError := userInterface.Input("\nAdd a reason for ignoring this issue [Y/N]?")
		if inputError != nil {
			return false, inputError
		}

		switch strings.ToLower(yesNoString) {
		case "y", "yes":
			return true, nil
		default:
			return false, nil
		}
	})
}

func getUserName(invocationCtx workflow.InvocationContext) (string, error) {
	data, err := invocationCtx.GetEngine().InvokeWithConfig(WORKFLOWID_WHOAMI, invocationCtx.GetConfiguration())
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
