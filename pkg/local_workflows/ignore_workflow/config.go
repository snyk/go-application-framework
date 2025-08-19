package ignore_workflow

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/go-application-framework/internal/api"
	policyApi "github.com/snyk/go-application-framework/internal/api/policy/2024-10-15"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/local_models"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/utils/git"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func addCreateIgnoreDefaultConfigurationValues(invocationCtx workflow.InvocationContext) {
	config := invocationCtx.GetConfiguration()

	config.AddDefaultValue(RemoteRepoUrlKey, func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		return remoteRepoUrlDefaultFunc(existingValue, config)
	})

	config.AddDefaultValue(IgnoreTypeKey, func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		isSet := config.IsSet(IgnoreTypeKey)
		return defaultFuncWithValidator(existingValue, isSet, isValidIgnoreType)
	})

	config.AddDefaultValue(ExpirationKey, func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		isSet := config.IsSet(ExpirationKey)
		return defaultFuncWithValidator(existingValue, isSet, isValidExpirationDate)
	})

	config.AddDefaultValue(FindingsIdKey, func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		isSet := config.IsSet(FindingsIdKey)
		return defaultFuncWithValidator(existingValue, isSet, isValidFindingsId)
	})

	config.AddDefaultValue(ReasonKey, func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		isSet := config.IsSet(ReasonKey)
		return defaultFuncWithValidator(existingValue, isSet, isValidReason)
	})
}

func getOrgIgnoreApprovalEnabled(engine workflow.Engine) configuration.DefaultValueFunction {
	return func(_ configuration.Configuration, existingValue interface{}) (interface{}, error) {
		if existingValue != nil {
			return existingValue, nil
		}

		config := engine.GetConfiguration()
		org := config.GetString(configuration.ORGANIZATION)
		client := engine.GetNetworkAccess().GetHttpClient()
		url := config.GetString(configuration.API_URL)
		apiClient := api.NewApi(url, client)

		settings, err := apiClient.GetOrgSettings(org)
		if err != nil {
			engine.GetLogger().Err(err).Msg("Failed to access settings.")
			return nil, err
		}

		if settings.Ignores != nil && settings.Ignores.ApprovalWorkflowEnabled {
			return true, nil
		}

		return false, nil
	}
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

func defaultFuncWithValidator(existingValue interface{}, isFlagSet bool, validatorFunc func(string) error) (interface{}, error) {
	if isFlagSet {
		value, ok := existingValue.(string)
		if !ok {
			return "", cli.NewValidationFailureError("Value must be a string. Ensure the provided value is a string.")
		}

		err := validatorFunc(value)
		if err != nil {
			return "", err
		}
		return existingValue, nil
	}

	return "", nil
}

func promptIfEmpty(value string, userInterface ui.UserInterface, promptHelp string, prompt string, validator func(string) error) (string, error) {
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

	err = validator(input)
	if err != nil {
		return "", err
	}

	return input, nil
}

func isValidIgnoreType(input string) error {
	ignoreTypeMapped := policyApi.PolicyActionIgnoreDataIgnoreType(input)
	validIgnoreType := ignoreTypeMapped == policyApi.TemporaryIgnore || ignoreTypeMapped == policyApi.WontFix || ignoreTypeMapped == policyApi.NotVulnerable
	if !validIgnoreType {
		errMsg := fmt.Sprintf("Invalid ignore type: '%s'. Valid types are: %s, %s, or %s.",
			input,
			policyApi.NotVulnerable, policyApi.WontFix, policyApi.TemporaryIgnore)
		return cli.NewValidationFailureError(errMsg)
	}
	return nil
}

func isValidFindingsId(input string) error {
	_, err := uuid.Parse(input)
	if err != nil {
		return cli.NewValidationFailureError(fmt.Sprintf("Invalid Finding ID format: '%s'. Ensure the Finding ID is a valid UUID.", input))
	}
	return nil
}

func isValidReason(input string) error {
	if input == "" {
		return cli.NewValidationFailureError("The ignore reason cannot be empty. Provide a justification for ignoring this finding.")
	}
	return nil
}

func isValidExpirationDate(input string) error {
	if input == "" {
		return cli.NewValidationFailureError("The expiriration date cannot be empty. Use YYYY-MM-DD format or use 'never' for no expiration.")
	}

	if input == local_models.DefaultSuppressionExpiration {
		return nil
	}

	_, parseErr := time.Parse(time.DateOnly, input)
	if parseErr != nil {
		return cli.NewValidationFailureError(fmt.Sprintf("Invalid expiration date format: '%s'. Use YYYY-MM-DD format or use 'never' for no expiration.", input))
	}
	return nil
}

func isValidInteractiveExpiration(input string) error {
	// in interactive mode an empty user prompt means no expiration date
	if input == "" {
		return nil
	}

	_, parseErr := time.Parse(time.DateOnly, input)
	if parseErr != nil {
		return cli.NewValidationFailureError(fmt.Sprintf("Invalid expiration date format: '%s'. Use YYYY-MM-DD format or leave empty for no expiration.", input))
	}

	return nil
}

func isValidRepoUrl(input string) error {
	if input == "" {
		return cli.NewValidationFailureError("The repository URL cannot be empty. Provide the URL for the remote repository.")
	}
	return nil
}
