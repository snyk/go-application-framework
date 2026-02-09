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
	noCheckFlag           = "no-check"
	defaultRegion         = "snyk-us-01"
)

var regions = []SnykRegion{
	{alias: "snyk-us-01", url: "https://api.snyk.io"},
	{alias: "snyk-us-02", url: "https://api.us.snyk.io"},
	{alias: "snyk-au-01", url: "https://api.au.snyk.io"},
	{alias: "snyk-eu-01", url: "https://api.eu.snyk.io"},
	{alias: "snyk-gov-01", url: "https://api.snykgov.io"},
}

var WORKFLOWID_CONFIG_ENVIRONMENT workflow.Identifier = workflow.NewWorkflowIdentifier(configEnvWorkflowName)

func InitConfigWorkflow(engine workflow.Engine) error {
	// map environmentAlias to an existing value
	engine.GetConfiguration().AddAlternativeKeys(environmentAlias, []string{configuration.INPUT_DIRECTORY})

	// register workflow with engine
	flags := pflag.NewFlagSet(configEnvWorkflowName, pflag.ExitOnError)
	flags.Bool(noCheckFlag, false, "use to disable sanity checks")
	_, err := engine.Register(WORKFLOWID_CONFIG_ENVIRONMENT, workflow.ConfigurationOptionsFromFlagset(flags), configEnvironmentWorkflowEntryPoint)
	return err
}

type SnykRegion struct {
	alias string
	url   string
}

func DetermineRegionFromUrl(url string) (string, error) {
	if len(url) == 0 {
		return "", fmt.Errorf("url must not be empty")
	}

	// Loop through each region and check for a match in the URL host
	for _, region := range regions {
		if strings.HasPrefix(url, region.url) {
			return region.alias, nil
		}
	}

	// If no match found, throw an error
	return "", fmt.Errorf("no region found for the given URL")
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

	// lookup if alias can be directly mapped to a URL
	if alias == "default" {
		alias = defaultRegion
	}

	for _, region := range regions {
		if region.alias == strings.ToLower(alias) {
			return region.url, nil
		}
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

func sanityCheck(config configuration.Configuration) error {
	keys := []string{configuration.API_URL, configuration.AUTHENTICATION_TOKEN, configuration.AUTHENTICATION_BEARER_TOKEN, configuration.ORGANIZATION}
	envVars := []string{}

	for _, key := range keys {
		keysSpecified := config.GetAllKeysThatContainValues(key)
		for _, specifiedKey := range keysSpecified {
			if config.GetKeyType(specifiedKey) == configuration.EnvVarKeyType {
				envVars = append(envVars, strings.ToUpper(specifiedKey))
			}
		}
	}

	if len(envVars) > 0 {
		tmp := cli_error.NewConfigEnvironmentConsistencyIssueError(fmt.Sprintf("The following existing configuration values might cause unexpected behavior: `%v`", strings.Join(envVars, "`, `")))
		tmp.StatusCode = 0
		return tmp
	}

	return nil
}

func configEnvironmentWorkflowEntryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (result []workflow.Data, err error) {
	// get necessary objects from invocation context
	config := invocationCtx.GetConfiguration()
	logger := invocationCtx.GetEnhancedLogger()
	userInterface := invocationCtx.GetUserInterface()

	failOnCheck := !config.GetBool(noCheckFlag)
	envAlias := config.GetString(environmentAlias)
	currentUrl := config.GetString(configuration.API_URL)
	newEnvUrl, err := determineUrlFromAlias(envAlias)

	logger.Print("Alias: ", envAlias)
	logger.Print("Previous Environment: ", currentUrl)
	logger.Print("New Environment: ", newEnvUrl)
	logger.Print("Fail on Sanity Check: ", failOnCheck)

	if failOnCheck {
		localError := sanityCheck(config)
		if localError != nil {
			return nil, localError
		}
	}

	if err != nil {
		logger.Err(err).Msg("No Url could be derived from the given alias!")

		pattern := "The specified environment cannot be used. As a result, the configuration remains unchanged. Provide the correct specifications for the environment and try again.\n\n(%s)"
		tmp := cli_error.NewConfigEnvironmentFailedError(fmt.Sprintf(pattern, err.Error()))
		tmp.StatusCode = 0
		return result, tmp
	}

	if currentUrl == newEnvUrl {
		uiErr := userInterface.Output(fmt.Sprintf("You are already using environment \"%s\".", newEnvUrl))
		if uiErr != nil {
			logger.Print(uiErr)
		}

		return result, err
	}

	config.Unset(configuration.ORGANIZATION)
	config.Unset(configuration.AUTHENTICATION_TOKEN)
	config.Unset(auth.CONFIG_KEY_OAUTH_TOKEN)

	uiErr := userInterface.Output(fmt.Sprintf("You are now using the environment \"%s\".", newEnvUrl))
	if uiErr != nil {
		logger.Print(uiErr)
	}

	config.PersistInStorage(configuration.API_URL)
	config.Set(configuration.API_URL, newEnvUrl)

	return result, err
}
