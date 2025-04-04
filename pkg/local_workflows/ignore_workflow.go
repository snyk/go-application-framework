package localworkflows

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/spf13/pflag"

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

	userName, _ := getUserName(invocationCtx)
	//if err != nil {
	//	return nil, err
	//}

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
		expire, err = time.Parse(time.DateOnly, expireStr)
		if err != nil {
			return nil, err
		}
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
