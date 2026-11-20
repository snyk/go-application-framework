package app

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/profile"
)

// IdentityEnvVars are the environment variable names that must not affect credentials under a
// named config profile. Proxy, certificate, and API URL variables are intentionally absent.
func IdentityEnvVars() []string {
	return []string{
		"SNYK_TOKEN",
		"SNYK_CFG_API",
		"SNYK_OAUTH_TOKEN",
		"SNYK_DOCKER_TOKEN",
		"INTERNAL_OAUTH_TOKEN_STORAGE",
		"INTERNAL_MACHINE_IDENTITY_STORAGE",
		"INTERNAL_NEW_SNYK_TOKEN",
	}
}

// IgnoreIdentityEnvVarsForProfile applies the identity environment ignore list and records the
// profile marker on a derived named-profile configuration. It is intended as a
// profile.ConfigEnrichment for hosts that opt in.
func IgnoreIdentityEnvVarsForProfile(name string, config configuration.Configuration) error {
	if config == nil {
		return nil
	}
	if setter, ok := config.(interface{ SetIgnoredEnvVars(...string) }); ok {
		setter.SetIgnoredEnvVars(IdentityEnvVars()...)
	}
	profile.SetMarker(config, name)
	return nil
}
