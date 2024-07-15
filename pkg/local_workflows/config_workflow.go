package localworkflows

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	cli_error "github.com/snyk/error-catalog-golang-public/cli"
	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	configEnvWorkflowName = "config.environment"
	environmentAlias      = "internal_environment_name"
)

var WORKFLOWID_CONFIG_ENVIRONMENT workflow.Identifier = workflow.NewWorkflowIdentifier(configEnvWorkflowName)

func InitConfigWorkflow(engine workflow.Engine) error {
	// map environmentAlias to an existing value
	engine.GetConfiguration().AddAlternativeKeys(environmentAlias, []string{configuration.INPUT_DIRECTORY})

	// register workflow with engine
	flags := pflag.NewFlagSet(codeWorkflowName, pflag.ExitOnError)
	_, err := engine.Register(WORKFLOWID_CONFIG_ENVIRONMENT, workflow.ConfigurationOptionsFromFlagset(flags), configEnvironmentWorkflowEntryPoint)
	return err
}

func determineUrlFromAlias(alias string) (string, error) {
	if len(alias) == 0 {
		return "", fmt.Errorf("environment alias must not be empty")
	}

	var urlString string
	var envUrl *url.URL
	var err error

	dnsPattern := "https://api.%s.snyk.io"
	supportedUrlSchemes := []string{"http", "https"}
	knownAliases := map[string]string{
		"default":    "https://api.snyk.io",
		"snyk-us-01": "https://api.us1.snyk.io",
	}

	// lookup if alias can be directly mapped to a URL
	urlString, aliasFound := knownAliases[strings.ToLower(alias)]
	if aliasFound {
		return urlString, nil
	}

	// test if the alias is already an url?
	envUrl, err = url.Parse(alias)
	if err == nil && slices.Contains(supportedUrlSchemes, envUrl.Scheme) {
		urlString, err = api.GetCanonicalApiUrl(*envUrl)
		if err != nil {
			return "", err
		}
	} else { // attempt to use the alias with a dns name pattern as is
		urlString = fmt.Sprintf(dnsPattern, alias)
	}

	envUrl, err = url.Parse(urlString)
	if err != nil {
		return "", err
	}

	// test if the url is can be looked up
	addr, err := net.LookupHost(envUrl.Host)
	if err != nil {
		return "", err
	}

	if len(addr) > 0 {
		return envUrl.String(), nil
	}

	return "", fmt.Errorf("failed to derive evironment url")
}

func configEnvironmentWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (result []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	ui := invocationCtx.GetUserInterface()

	envAlias := config.GetString(environmentAlias)
	currentUrl := config.GetString(configuration.API_URL)
	newEnvUrl, err := determineUrlFromAlias(envAlias)

	logger.Print("Alias: ", envAlias)
	logger.Print("Previous Environment: ", currentUrl)
	logger.Print("New Environment: ", newEnvUrl)

	if err != nil {
		logger.Err(err).Msg("No Url could be derived from the given alias!")

		pattern := "The specified environment cannot be used. As a result, the configuration remains unchanged. Provide the correct specifications for the environment and try again.\n\n(%s)"
		tmp := cli_error.NewConfigEnvironmentFailedError(fmt.Sprintf(pattern, err.Error()))
		tmp.StatusCode = 0
		return result, tmp
	}

	if currentUrl == newEnvUrl {
		uiErr := ui.Output(fmt.Sprintf("You are already using environment \"%s\".", newEnvUrl))
		if uiErr != nil {
			logger.Print(uiErr)
		}

		return result, err
	}

	config.Unset(configuration.ORGANIZATION)
	config.Unset(configuration.AUTHENTICATION_TOKEN)
	config.Unset(auth.CONFIG_KEY_OAUTH_TOKEN)

	uiErr := ui.Output(fmt.Sprintf("You are now using the environment \"%s\".", newEnvUrl))
	if uiErr != nil {
		logger.Print(uiErr)
	}

	config.PersistInStorage(configuration.API_URL)
	config.Set(configuration.API_URL, newEnvUrl)

	return result, err
}
