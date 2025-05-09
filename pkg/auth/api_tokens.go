package auth

import (
	"fmt"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// GetAuthHeader returns the authentication header value based on the configuration.
func GetAuthHeader(config configuration.Configuration) string {
	bearerToken := config.GetString(configuration.AUTHENTICATION_BEARER_TOKEN)
	if len(bearerToken) > 0 {
		return fmt.Sprintf("Bearer %s", bearerToken)
	}

	patToken := config.GetString(configuration.AUTHENTICATION_PAT_TOKEN)
	if len(patToken) > 0 {
		return fmt.Sprintf("PAT %s", patToken)
	}

	token := config.GetString(configuration.AUTHENTICATION_TOKEN)
	if len(token) > 0 {
		return fmt.Sprintf("token %s", token)
	}

	return ""
}

// GetAuthType returns the authentication type based on the configuration
func GetAuthType(config configuration.Configuration) string {
	if len(config.GetString(configuration.AUTHENTICATION_BEARER_TOKEN)) > 0 {
		return config.GetString(configuration.AUTHENTICATION_BEARER_TOKEN)
	}

	if len(config.GetString(configuration.AUTHENTICATION_PAT_TOKEN)) > 0 {
		return config.GetString(configuration.AUTHENTICATION_PAT_TOKEN)
	}

	if len(config.GetString(configuration.AUTHENTICATION_TOKEN)) > 0 {
		return config.GetString(configuration.AUTHENTICATION_TOKEN)
	}

	return ""
}
