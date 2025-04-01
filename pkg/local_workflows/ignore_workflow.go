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
	reasonKey                = "reason"
	reasonDescription        = "Reason"
	expirationKey            = "expires"
	expirationDescription    = "Expiration (YYYY-MM-DD)"
)

var WORKFLOWID_IGNORE_CREATE workflow.Identifier = workflow.NewWorkflowIdentifier(ignoreCreateWorkflowName)

func InitIgnoreWorkflows(engine workflow.Engine) error {
	flagset := pflag.NewFlagSet(ignoreCreateWorkflowName, pflag.ExitOnError)
	flagset.String(reasonKey, "", reasonDescription)
	flagset.String(expirationKey, "", expirationDescription)
	flagset.Bool("interactive", true, "")
	flagset.String(code_workflow.ConfigurationRemoteRepoUrlFlagname, "", "")

	_, err := engine.Register(WORKFLOWID_IGNORE_CREATE, workflow.ConfigurationOptionsFromFlagset(flagset), ignoreCreateWorkflowEntryPoint)
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

func ignoreCreateWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (output []workflow.Data, err error) {
	logger := invocationCtx.GetEnhancedLogger()
	userInterface := invocationCtx.GetUserInterface()
	config := invocationCtx.GetConfiguration()
	enterReasonKey := "internal_snyk_enterReasonKey"
	interactive := config.GetBool("interactive")

	if interactive {
		// add interactive default function
		config.AddDefaultValue(reasonKey, func(existingValue interface{}) (interface{}, error) {
			if existingValue != nil && existingValue != "" {
				return existingValue, nil
			}
			return userInterface.Input(reasonDescription)
		})

		config.AddDefaultValue(code_workflow.ConfigurationRemoteRepoUrlFlagname, func(existingValue interface{}) (interface{}, error) {
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
				return userInterface.Input("Repourl")
			}

			return repoUrl, nil
		})

		config.AddDefaultValue(enterReasonKey, func(existingValue interface{}) (interface{}, error) {
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

	repourl, err := config.GetWithError(code_workflow.ConfigurationRemoteRepoUrlFlagname)
	if err != nil {
		return nil, err
	}

	userInterface.Output(repourl)

	// get user
	config.Set(configuration.FLAG_EXPERIMENTAL, true)
	data, err := invocationCtx.GetEngine().InvokeWithConfig(WORKFLOWID_WHOAMI, config)
	if err != nil {
		return output, err
	}

	userName := "unknown"
	if len(data) > 0 {
		userName = data[0].GetPayload().(string)
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
		userInterface.Output("You are about to ignore the following issue:\n👉🏼 Make sure the code containing the issue is committed, and pushed to a remote origin, so the approvers are able to analyze it.\n")
		userInterface.Output(getIgnoreRequestDetailsStructure(expire, userName))
	}

	reason := ""
	if !config.IsSet(reasonKey) && config.GetBool(enterReasonKey) {
		reason = config.GetString(reasonKey)
	}

	logger.Printf("Reason: %s\n", reason)
	logger.Printf("Expires: %s\n", expire)

	sendRequest()

	if interactive {
		userInterface.Output("\nYour ignore request has been submitted for approval.")
	}

	return output, err
}
