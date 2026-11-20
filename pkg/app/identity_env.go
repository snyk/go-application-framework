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

// IdentityIgnoreDeriveOpts returns Derive options that ignore identity environment variables.
// Pass them to workflow.SetProfileDeriveOpts so named profiles apply the ignores at construction
// time, before any configuration read can bind ambient values.
func IdentityIgnoreDeriveOpts() []configuration.Opts {
	return []configuration.Opts{configuration.WithIgnoredEnvVars(IdentityEnvVars()...)}
}

// IgnoreIdentityEnvVarsForProfile records the profile marker on a derived named-profile
// configuration. It is intended as a profile.ConfigEnrichment for hosts that opt in.
//
// Identity environment ignores must be applied at Derive time via IdentityIgnoreDeriveOpts and
// workflow.SetProfileDeriveOpts (or profile.WithDeriveOpts). Applying them here after Derive would
// be too late once a key has already been read and bound.
func IgnoreIdentityEnvVarsForProfile(name string, config configuration.Configuration) error {
	profile.SetMarker(config, name)
	return nil
}
