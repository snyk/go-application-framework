package config_utils

import (
	"fmt"
	"strings"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils"
)

type SanityCheckResult struct {
	Description string
}

func CheckSanity(config configuration.Configuration) []SanityCheckResult {
	var result []SanityCheckResult

	keys := []string{configuration.API_URL, configuration.AUTHENTICATION_TOKEN, configuration.AUTHENTICATION_BEARER_TOKEN, configuration.ORGANIZATION}
	for _, key := range keys {
		keysSpecified := config.GetAllKeysThatContainValues(key)
		if len(keysSpecified) > 1 {
			result = append(result, SanityCheckResult{
				Description: fmt.Sprintf("Possible unexpected behavior, the following configuration values might override each other %s", strings.ToUpper(strings.Join(keysSpecified, ", "))),
			})
		}
	}

	if keysSpecified := config.GetAllKeysThatContainValues(configuration.API_URL); len(keysSpecified) > 0 {
		audience, err := auth.GetAudienceClaimFromOauthToken(config)
		if err == nil && len(audience) > 0 {
			clonedConfig := config.Clone()
			clonedConfig.DisableDefaultFunctions(true)
			configuredValue := clonedConfig.GetString(configuration.API_URL)
			differentApiUrlsSpecified := utils.ValueOf(api.GetCanonicalApiUrlFromString(audience[0])) != utils.ValueOf(api.GetCanonicalApiUrlFromString(configuredValue))

			if differentApiUrlsSpecified {
				result = append(result, SanityCheckResult{
					Description: fmt.Sprintf("Using API Url from authentication material, therefore ignoring the specified %s.", strings.ToUpper(strings.Join(keysSpecified, ", "))),
				})
			}
		}
	}

	return result
}
