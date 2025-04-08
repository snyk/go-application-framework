package ignore_workflow

import (
	"fmt"

	policyApi "github.com/snyk/go-application-framework/internal/api/policy/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/utils/git"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func addCreateIgnoreDefaultConfigurationValues(invocationCtx workflow.InvocationContext) {
	config := invocationCtx.GetConfiguration()
	userInterface := invocationCtx.GetUserInterface()

	config.AddDefaultValue(findingsIdKey, func(existingValue interface{}) (interface{}, error) {
		if existingValue != nil && existingValue != "" {
			return existingValue, nil
		}
		return userInterface.Input(findingsIdDescription)
	})

	config.AddDefaultValue(ignoreTypeKey, func(existingValue interface{}) (interface{}, error) {
		return ignoreTypeDefaultFunc(existingValue, userInterface)
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
		return userInterface.Input(expirationDescription)
	})

	config.AddDefaultValue(remoteRepoUrlKey, func(existingValue interface{}) (interface{}, error) {
		return remoteRepoUrlDefaultFunc(existingValue, config, userInterface)
	})
}

func remoteRepoUrlDefaultFunc(existingValue interface{}, config configuration.Configuration, userInterface ui.UserInterface) (interface{}, error) {
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
}

func ignoreTypeDefaultFunc(existingValue interface{}, userInterface ui.UserInterface) (interface{}, error) {
	invalidIgnoreTypeErr := fmt.Errorf("invalid ignore type, valid ignore types are: %s, %s, %s",
		policyApi.NotVulnerable, policyApi.TemporaryIgnore, policyApi.WontFix)

	if existingValue != nil && existingValue != "" {
		ignoreType, ok := existingValue.(string)
		if !ok || !isValidIgnoreType(ignoreType) {
			return "", invalidIgnoreTypeErr
		}
		return existingValue, nil
	}

	ignoreType, err := userInterface.Input(ignoreTypeDescription)
	if err != nil {
		return "", err
	}
	if !isValidIgnoreType(ignoreType) {
		return "", invalidIgnoreTypeErr
	}
	return ignoreType, nil
}

func isValidIgnoreType(ignoreType string) bool {
	ignoreTypeMapped := policyApi.PolicyActionIgnoreDataIgnoreType(ignoreType)
	return ignoreTypeMapped == policyApi.TemporaryIgnore || ignoreTypeMapped == policyApi.WontFix || ignoreTypeMapped == policyApi.NotVulnerable
}
