package configtest

import "testing"

// snykAPIKey is the AutomaticEnv name for configuration.API_URL (viper key "snyk_api").
// Keep aligned with pkg/configuration/constants.go.
const snykAPIKey = "SNYK_API"

// KnownLeakEnvironmentKeys is cleared when [IsolateEnvironmentForTest] is called with no arguments.
var KnownLeakEnvironmentKeys = []string{
	snykAPIKey,
}

// IsolateEnvironmentForTest runs t.Setenv(k, "") for each key. With no keys it clears [KnownLeakEnvironmentKeys].
// With keys, only those are cleared (not merged with defaults). Empty keys are skipped.
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
