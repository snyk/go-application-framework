package ignore_workflow

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/snyk/error-catalog-golang-public/cli"
	policyApi "github.com/snyk/go-application-framework/internal/api/policy/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/utils/git"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func addCreateIgnoreDefaultConfigurationValues(invocationCtx workflow.InvocationContext) {
	config := invocationCtx.GetConfiguration()

	config.AddDefaultValue(RemoteRepoUrlKey, func(existingValue interface{}) (interface{}, error) {
		return remoteRepoUrlDefaultFunc(existingValue, config)
	})

	config.AddDefaultValue(IgnoreTypeKey, func(existingValue interface{}) (interface{}, error) {
		isSet := config.IsSet(IgnoreTypeKey)
		return defaultFuncWithValidator(existingValue, isSet, isValidIgnoreType)
	})

	config.AddDefaultValue(ExpirationKey, func(existingValue interface{}) (interface{}, error) {
		isSet := config.IsSet(ExpirationKey)
		return defaultFuncWithValidator(existingValue, isSet, isValidExpirationDate)
	})

	config.AddDefaultValue(FindingsIdKey, func(existingValue interface{}) (interface{}, error) {
		isSet := config.IsSet(FindingsIdKey)
		return defaultFuncWithValidator(existingValue, isSet, isValidFindingsId)
	})

	config.AddDefaultValue(ReasonKey, func(existingValue interface{}) (interface{}, error) {
		isSet := config.IsSet(ReasonKey)
		return defaultFuncWithValidator(existingValue, isSet, isValidReason)
	})
}

func remoteRepoUrlDefaultFunc(existingValue interface{}, config configuration.Configuration) (interface{}, error) {
	if existingValue != nil && existingValue != "" {
		return existingValue, nil
	}

	isInteractive := config.GetBool(InteractiveKey)

	repoUrl, err := git.RepoUrlFromDir(config.GetString(configuration.INPUT_DIRECTORY))
	if err != nil && isInteractive {
		return "", nil
	} else if err != nil {
		return "", err
	}

	return repoUrl, nil
}

func defaultFuncWithValidator(existingValue interface{}, isFlagSet bool, validatorFunc func(interface{}) error) (interface{}, error) {
	if isFlagSet {
		err := validatorFunc(existingValue)
		if err != nil {
			return "", err
		}
		return existingValue, nil
	}

	return "", nil
}

func promptIfEmpty(value string, userInterface ui.UserInterface, promptHelp string, prompt string, validator func(interface{}) error) (string, error) {
	if value != "" {
		return value, nil
	}

	helperText := "<p class='prompt-help'>" + promptHelp + "</p>"
	err := userInterface.Output(helperText)
	if err != nil {
		return "", err
	}

	input, err := userInterface.Input(prompt)
	if err != nil {
		return "", err
	}

	err = userInterface.Output("") // new line between prompts
	if err != nil {
		return "", err
	}

	err = validator(input)
	if err != nil {
		return "", err
	}

	return input, nil
}

func isValidIgnoreType(input interface{}) error {
	ignoreType, ok := input.(string)
	if !ok {
		return cli.NewValidationFailureError("Ignore type must be a string. Ensure the provided value is a string.")
	}

	ignoreTypeMapped := policyApi.PolicyActionIgnoreDataIgnoreType(ignoreType)
	validIgnoreType := ignoreTypeMapped == policyApi.TemporaryIgnore || ignoreTypeMapped == policyApi.WontFix || ignoreTypeMapped == policyApi.NotVulnerable
	if !validIgnoreType {
		errMsg := fmt.Sprintf("Invalid ignore type: '%s'. Valid types are: %s, %s, or %s.",
			ignoreType,
			policyApi.NotVulnerable, policyApi.WontFix, policyApi.TemporaryIgnore)
		return cli.NewValidationFailureError(errMsg)
	}
	return nil
}

func isValidFindingsId(input interface{}) error {
	uuidStr, ok := input.(string)
	if !ok {
		return cli.NewValidationFailureError("Finding ID must be a string. Provide a valid UUID as the Finding ID.")
	}
	_, err := uuid.Parse(uuidStr)
	if err != nil {
		return cli.NewValidationFailureError(fmt.Sprintf("Invalid Finding ID format: '%s'. Ensure the Finding ID is a valid UUID.", uuidStr))
	}
	return nil
}

func isValidReason(input interface{}) error {
	reasonStr, ok := input.(string)
	if !ok {
		return cli.NewValidationFailureError("Reason must be a string. Provide a textual reason for the ignore.")
	}
	if reasonStr == "" {
		return cli.NewValidationFailureError("The ignore reason cannot be empty. Provide a justification for ignoring this finding.")
	}
	return nil
}

func isValidExpirationDate(input interface{}) error {
	dateStr, ok := input.(string)
	if !ok {
		return cli.NewValidationFailureError("Expiration date must be a string. Use YYYY-MM-DD format or use 'never' for no expiration.")
	}

	if dateStr == "" {
		return cli.NewValidationFailureError("The expiriration date cannot be empty. Use YYYY-MM-DD format or use 'never' for no expiration.")
	}

	if dateStr == "never" {
		return nil
	}

	_, parseErr := time.Parse(time.DateOnly, dateStr)
	if parseErr != nil {
		return cli.NewValidationFailureError(fmt.Sprintf("Invalid expiration date format: '%s'. Use YYYY-MM-DD format or use 'never' for no expiration.", dateStr))
	}
	return nil
}

func isValidInteractiveExpiration(input interface{}) error {
	dateStr, ok := input.(string)
	if !ok {
		return cli.NewValidationFailureError("Expiration date must be a string. Use YYYY-MM-DD format or leave empty for no expiration.")
	}

	// in interactive mode an empty user prompt means no expiration date
	if dateStr == "" {
		return nil
	}

	_, parseErr := time.Parse(time.DateOnly, dateStr)
	if parseErr != nil {
		return cli.NewValidationFailureError(fmt.Sprintf("Invalid expiration date format: '%s'. Use YYYY-MM-DD format or leave empty for no expiration.", dateStr))
	}

	return nil
}

func isValidRepoUrl(input interface{}) error {
	repoUrl, ok := input.(string)
	if !ok {
		return cli.NewValidationFailureError("Repository URL must be a string. Provide a valid repository URL.")
	}
	if repoUrl == "" {
		return cli.NewValidationFailureError("The repository URL cannot be empty. Provide the URL for the remote repository.")
	}
	return nil
}
