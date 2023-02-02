package app

import (
	"log"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/internal/utils"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/snyk/go-httpauth/pkg/httpauth"
)

func initConfiguration(config configuration.Configuration, apiClient api.ApiClient) {
	dir, _ := utils.SnykCacheDir()

	config.AddDefaultValue(configuration.ANALYTICS_DISABLED, configuration.StandardDefaultValueFunction(false))
	config.AddDefaultValue(configuration.WORKFLOW_USE_STDIO, configuration.StandardDefaultValueFunction(false))
	config.AddDefaultValue(configuration.PROXY_AUTHENTICATION_MECHANISM, configuration.StandardDefaultValueFunction(httpauth.StringFromAuthenticationMechanism(httpauth.AnyAuth)))
	config.AddDefaultValue(configuration.DEBUG_FORMAT, configuration.StandardDefaultValueFunction(log.Ldate|log.Ltime|log.Lmicroseconds|log.Lmsgprefix|log.LUTC))
	config.AddDefaultValue(configuration.CACHE_PATH, configuration.StandardDefaultValueFunction(dir))

	config.AddDefaultValue(configuration.API_URL, func(existingValue any) any {
		if existingValue == nil {
			return constants.SNYK_DEFAULT_API_URL
		} else {
			apiString := existingValue
			if temp, ok := existingValue.(string); ok {
				if apiUrl, err := url.Parse(temp); err == nil {
					apiUrl.Path = strings.Replace(apiUrl.Path, "/v1", "", 1)
					apiString = apiUrl.String()
				}
			}
			return apiString
		}
	})

	config.AddDefaultValue(configuration.ORGANIZATION, func(existingValue any) any {
		client := networking.NewNetworkAccess(config).GetHttpClient()
		url := config.GetString(configuration.API_URL)
		apiClient.SetClient(client)
		apiClient.SetUrl(url)
		if existingValue != nil && len(existingValue.(string)) > 0 {
			orgId := existingValue.(string)
			_, err := uuid.Parse(orgId)
			isSlugName := err != nil
			if isSlugName {
				orgId, err = apiClient.GetOrgIdFromSlug(existingValue.(string))
				if err == nil {
					return orgId
				}
			}
			return orgId
		}

		orgId, _ := apiClient.GetDefaultOrgId()

		return orgId
	})

	config.AddAlternativeKeys(configuration.AUTHENTICATION_TOKEN, []string{"snyk_token", "snyk_cfg_api", "api"})
	config.AddAlternativeKeys(configuration.AUTHENTICATION_BEARER_TOKEN, []string{"snyk_oauth_token", "snyk_docker_token"})
}

func CreateAppEngine() workflow.Engine {
	config := configuration.New()
	apiClient := api.NewApiInstance()

	initConfiguration(config, apiClient)

	engine := workflow.NewWorkFlowEngine(config)

	engine.AddExtensionInitializer(localworkflows.Init)

	return engine
}
