package configtest

import (
	"testing"
)

// snykAPIKey is the AutomaticEnv name for configuration.API_URL (viper key "snyk_api").
// Keep aligned with pkg/configuration/constants.go.
const snykAPIKey = "SNYK_API"

// KnownLeakEnvironmentKeys is cleared when [IsolateEnvironmentForTest] is called with no arguments.
var KnownLeakEnvironmentKeys = []string{
	snykAPIKey,
}

// IsolateEnvironmentForTest clears environment variables for a test using t.Setenv(k, "").
// If no keys are provided, it clears the variables listed in [KnownLeakEnvironmentKeys].
// If explicit keys are provided, they OVERRIDE the default behavior: only the specified keys are cleared,
// and they are NOT merged with [KnownLeakEnvironmentKeys]. Empty keys are skipped.
func IsolateEnvironmentForTest(t *testing.T, keys ...string) {
	t.Helper()
	toClear := keys
	if len(toClear) == 0 {
		toClear = KnownLeakEnvironmentKeys
	}
	for _, k := range toClear {
		if k == "" {
			continue
		}
		t.Setenv(k, "")
	}
}
