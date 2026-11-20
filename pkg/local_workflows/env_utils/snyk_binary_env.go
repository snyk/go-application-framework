// Package env_utils holds small, pure helpers for preparing process environments.
package env_utils

import (
	"strings"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/profile"
)

// Environment variable names that select a config profile for a Snyk binary child process.
const (
	ConfigProfileEnvVar    = "SNYK_CONFIG_PROFILE"
	ConfigProfileDirEnvVar = "SNYK_CONFIG_PROFILE_DIR"
)

// PrepareSnykBinaryEnvironment returns a copy of env with SNYK_CONFIG_PROFILE and
// SNYK_CONFIG_PROFILE_DIR set from config when a named profile is active.
// Identity environment variables are left in place: a Snyk child that loads the same
// named profile ignores them itself. The input slice is not modified.
func PrepareSnykBinaryEnvironment(env []string, config configuration.Configuration) []string {
	result := append([]string(nil), env...)
	if config == nil || !profile.IsProfile(config) {
		return result
	}

	name := profile.Name(config)
	dir := config.GetString(profile.DirKey)
	result = upsertEnv(result, ConfigProfileEnvVar, name)
	if dir != "" {
		result = upsertEnv(result, ConfigProfileDirEnvVar, dir)
	}
	return result
}

func upsertEnv(env []string, key, value string) []string {
	for i, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, key) {
			env[i] = key + "=" + value
			return env
		}
	}
	return append(env, key+"="+value)
}
