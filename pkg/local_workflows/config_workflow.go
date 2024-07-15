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
	var envUrl *url.URL
	var err error

	dnsPattern := "https://api.%s.snyk.io"
	supportedUrlSchemes := []string{"http", "https"}
	knownAliases := map[string]string{
		"DEFAULT":    "https://api.snyk.io",
		"SNYK-US-01": "https://api.us1.snyk.io",
	}

	// lookup alias
	lookedUpUrl, aliasFound := knownAliases[strings.ToUpper(alias)]
	if aliasFound {
		return lookedUpUrl, nil
	}

	// is alias an url already?
	envUrl, err = url.Parse(alias)
	if err == nil && slices.Contains(supportedUrlSchemes, envUrl.Scheme) {
		return api.GetCanonicalApiUrl(*envUrl)
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
	newEnvUrl, err := determineUrlFromAlias(envAlias)

	logger.Print("Alias: ", envAlias)
	logger.Print("Previous Environment: ", currentUrl)
	logger.Print("New Environment: ", newEnvUrl)

	if err != nil {
		logger.Err(err).Msg("No Url could be derived from the given alias!")

		tmp := cli_error.NewConfigEnvironmentFailedError("The specified environment cannot be used. As a result, the configuration remains unchanged. Provide the correct specifications for the environment and try again.")
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
