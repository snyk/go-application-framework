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

	token := config.GetString(configuration.AUTHENTICATION_TOKEN)
	authType := getAuthType(token)
	// validate token is Snyk PAT
	if len(token) > 0 && authType == AUTH_TYPE_PAT {
		return fmt.Sprintf("Bearer %s", token)
	}

	// otherwise validate that it is Snyk API
	if len(token) > 0 && authType == AUTH_TYPE_TOKEN {
		return fmt.Sprintf("token %s", token)
	}

	return ""
}

// getAuthType returns the authentication type (token/PAT) based on token input
func getAuthType(token string) string {
	if IsAuthTypePAT(token) {
		return AUTH_TYPE_PAT
	}

	if IsAuthTypeToken(token) {
		return AUTH_TYPE_TOKEN
	}

	return ""
}
