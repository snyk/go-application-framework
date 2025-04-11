package ignore_workflow

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	policyApi "github.com/snyk/go-application-framework/internal/api/policy/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/utils/git"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func addCreateIgnoreDefaultConfigurationValues(invocationCtx workflow.InvocationContext, interactive bool) {
	config := invocationCtx.GetConfiguration()
	userInterface := invocationCtx.GetUserInterface()

	config.AddDefaultValue(RemoteRepoUrlKey, func(existingValue interface{}) (interface{}, error) {
		return remoteRepoUrlDefaultFunc(existingValue, config, userInterface, interactive)
	})

	config.AddDefaultValue(IgnoreTypeKey, func(existingValue interface{}) (interface{}, error) {
		isSet := config.IsSet(IgnoreTypeKey)
		return defaultFuncWithValidator(existingValue, userInterface, interactive, isSet, ignoreTypeDescription, isValidIgnoreType)
	})

	config.AddDefaultValue(ExpirationKey, func(existingValue interface{}) (interface{}, error) {
		isSet := config.IsSet(ExpirationKey)
		return defaultFuncWithValidator(existingValue, userInterface, interactive, isSet, expirationDescription, isValidExpirationDate)
	})

	config.AddDefaultValue(FindingsIdKey, func(existingValue interface{}) (interface{}, error) {
		isSet := config.IsSet(FindingsIdKey)
		return defaultFuncWithValidator(existingValue, userInterface, interactive, isSet, findingsIdDescription, isValidUuid)
	})

	config.AddDefaultValue(ReasonKey, func(existingValue interface{}) (interface{}, error) {
		isSet := config.IsSet(ReasonKey)
		return defaultFuncWithValidator(existingValue, userInterface, interactive, isSet, reasonDescription, isValidReason)
	})
}

func remoteRepoUrlDefaultFunc(existingValue interface{}, config configuration.Configuration, userInterface ui.UserInterface, interactive bool) (interface{}, error) {
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

	if err != nil && interactive {
		return userInterface.Input(remoteRepoUrlDescription)
	} else if err != nil {
		return nil, err
	}

	return repoUrl, nil
}

func defaultFuncWithValidator(existingValue interface{}, userInterface ui.UserInterface, interactive bool, isFlagSet bool, inputDescription string, validatorFunc func(interface{}) error) (interface{}, error) {
	if isFlagSet {
		err := validatorFunc(existingValue)
		if err != nil {
			return "", err
		}
		return existingValue, nil
	}

	if !interactive {
		return "", fmt.Errorf("no value provided and interactive flag is false")
	}

	input, err := userInterface.Input(inputDescription)
	if err != nil {
		return "", err
	}

	err = validatorFunc(input)
	if err != nil {
		return "", err
	}
	return input, nil
}

func isValidIgnoreType(input interface{}) error {
	ignoreType, ok := input.(string)
	if !ok {
		return fmt.Errorf("invalid ignore type, expected string")
	}

	ignoreTypeMapped := policyApi.PolicyActionIgnoreDataIgnoreType(ignoreType)
	validIgnoreType := ignoreTypeMapped == policyApi.TemporaryIgnore || ignoreTypeMapped == policyApi.WontFix || ignoreTypeMapped == policyApi.NotVulnerable
	if !validIgnoreType {
		return fmt.Errorf("invalid ignore type, valid ignore types are: %s, %s, %s",
			policyApi.NotVulnerable, policyApi.TemporaryIgnore, policyApi.WontFix)
	}
	return nil
}

func isValidUuid(input interface{}) error {
	uuidStr, ok := input.(string)
	if !ok {
		return fmt.Errorf("invalid uuid input, expected string")
	}
	_, err := uuid.Parse(uuidStr)
	return err
}

func isValidReason(input interface{}) error {
	reasonStr, ok := input.(string)
	if !ok {
		return fmt.Errorf("invalid uuid input, expected string")
	}
	if reasonStr == "" {
		return fmt.Errorf("reason cannot be empty")
	}
	return nil
}

func isValidExpirationDate(input interface{}) error {
	// if date is nil we treat it as a valid case as a no-expire case
	if input == nil {
		return nil
	}
	dateStr, ok := input.(string)
	if !ok {
		return fmt.Errorf("invalid expiration date, expected string")
	}
	// if date is empty we treat it as a valid case as a no-expire case
	if dateStr == "" {
		return nil
	}

	_, parseErr := time.Parse(time.DateOnly, dateStr)
	return parseErr
}
