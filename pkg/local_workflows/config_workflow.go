package localworkflows

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/spf13/pflag"

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
	var envUrl *url.URL
	var err error

	dnsPattern := "https://api.%s.snyk.io"
	supportedUrlSchemes := []string{"http", "https"}
	knownAliases := map[string]string{
		"SNYK-US-01": "https://api.us1.snyk.io",
	}

	// lookup alias
	lookedUpUrl, aliasFound := knownAliases[strings.ToUpper(alias)]
	if aliasFound {
		envUrl, err = url.Parse(lookedUpUrl)
		return envUrl.String(), err
	}

	// is alias an url already?
	envUrl, err = url.Parse(alias)
	if err == nil && slices.Contains(supportedUrlSchemes, envUrl.Scheme) {
		return envUrl.String(), nil
	}

	// check dns name
	envUrl, err = url.Parse(fmt.Sprintf(dnsPattern, alias))
	if err != nil {
		return "", err
	}

	addr, err := net.LookupHost(envUrl.Host)
	if err != nil {
		return "", err
	}

	if len(addr) > 0 {
		return envUrl.String(), nil
	}

	return "", fmt.Errorf("failed to derive url")
}

func configEnvironmentWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (result []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	ui := invocationCtx.GetUserInterface()

	envAlias := config.GetString(environmentAlias)
	currentUrl := config.GetString(configuration.API_URL)
	envUrl, err := determineUrlFromAlias(envAlias)

	logger.Print("Alias: ", envAlias)
	logger.Print("Current: ", currentUrl)
	logger.Print("New: ", envUrl)

	if err != nil {
		logger.Err(err).Msg("No Url could be derived from the given alias!")

		// todo replace with error catalog error
		err = snyk_errors.Error{
			ErrorCode: "CLI-0001",
			Title:     "Failed to set environment!",
			Level:     "Critical",
			Cause:     err,
		}

		return result, err
	}

	if config.GetString(configuration.API_URL) == envUrl {
		uiErr := ui.Output(fmt.Sprintf("You are already using environment \"%s\".", envUrl))
		if uiErr != nil {
			logger.Print(uiErr)
		}

		return result, err
	}

	config.Unset(configuration.ORGANIZATION)
	config.Unset(configuration.AUTHENTICATION_TOKEN)
	config.Unset(auth.CONFIG_KEY_OAUTH_TOKEN)

	uiErr := ui.Output(fmt.Sprintf("You are now using the new environment \"%s\".", envUrl))
	if uiErr != nil {
		logger.Print(uiErr)
	}

	config.PersistInStorage(configuration.API_URL)
	config.Set(configuration.API_URL, envUrl)

	return result, err
}
