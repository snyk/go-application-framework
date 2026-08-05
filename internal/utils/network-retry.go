package utils

import "github.com/snyk/go-application-framework/pkg/configuration"

// NetworkRetriesEnabled reports whether opt-in resilient network retry
// behavior should be active, keeping the app.go default-attempts policy and
// the retry-middleware transport-error policy from drifting apart.
func NetworkRetriesEnabled(config configuration.Configuration) bool {
	return config.GetBool(configuration.PREVIEW_FEATURES_ENABLED) ||
		config.GetBool(configuration.NETWORK_REQUEST_RETRIES_ENABLED)
}
