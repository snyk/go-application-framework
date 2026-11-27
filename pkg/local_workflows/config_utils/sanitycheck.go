package config_utils

import (
	"fmt"
	"strings"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils"
)

const configCheckMismatchedUrlMsg = "\"Using API Url from authentication material, therefore ignoring the configured %s value.\""

type SanityCheckResult struct {
	Description string
}

// CheckIgnoredEnvVars reports, in one result, the environment variables that config ignores while they are set to a
// non-empty value. The result names the variables only, never their values. It returns nil when there are none.
func CheckIgnoredEnvVars(config configuration.Configuration) []SanityCheckResult {
	names := configuration.IgnoredEnvVarsThatAreSet(config)
	if len(names) == 0 {
		return nil
	}
	return []SanityCheckResult{{
		Description: fmt.Sprintf("Ignoring environment variable(s) %s: they are not applied to this configuration.",
			strings.ToUpper(strings.Join(names, ", "))),
	}}
}

func CheckSanity(config configuration.Configuration) []SanityCheckResult {
	result := CheckIgnoredEnvVars(config)

	keys := []string{configuration.API_URL, configuration.AUTHENTICATION_TOKEN, configuration.AUTHENTICATION_BEARER_TOKEN, configuration.ORGANIZATION, configuration.TENANT}
	for _, key := range keys {
		keysSpecified := config.GetAllKeysThatContainValues(key)
		if len(keysSpecified) > 1 {
			result = append(result, SanityCheckResult{
				Description: fmt.Sprintf("Possible unexpected behavior, the following configuration values might override each other %s", strings.ToUpper(strings.Join(keysSpecified, ", "))),
			})
		}
	}

	if keysSpecified := config.GetAllKeysThatContainValues(configuration.API_URL); len(keysSpecified) > 0 {
		audience, err := auth.GetAudienceClaimFromOauthToken(config.GetString(auth.CONFIG_KEY_OAUTH_TOKEN))
		if err == nil && len(audience) > 0 {
			clonedConfig := config.Clone()
			clonedConfig.AddDefaultValue(configuration.API_URL, nil)
			configuredValue := clonedConfig.GetString(configuration.API_URL)
			differentApiUrlsSpecified := utils.ValueOf(api.GetCanonicalApiUrlFromString(audience[0])) != utils.ValueOf(api.GetCanonicalApiUrlFromString(configuredValue))

			if differentApiUrlsSpecified {
				result = append(result, SanityCheckResult{
					Description: fmt.Sprintf(configCheckMismatchedUrlMsg, strings.ToUpper(strings.Join(keysSpecified, ", "))),
				})
			}
		}
	}

	if warning := configuration.WorkingDirConfigFileWarning(config); warning != "" {
		result = append(result, SanityCheckResult{Description: warning})
	}

	return result
}
