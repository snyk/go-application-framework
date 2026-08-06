package utils

import "github.com/snyk/go-application-framework/pkg/configuration"

// Keeps app.go's default-attempts policy and the retry-middleware transport-error policy from drifting apart.
func NetworkRetriesEnabled(config configuration.Configuration) bool {
	return config.GetBool(configuration.PREVIEW_FEATURES_ENABLED) ||
		config.GetBool(configuration.NETWORK_REQUEST_RETRIES_ENABLED)
}
