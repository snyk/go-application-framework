package app

import (
	"io"
	"log"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/profile"
)

func Test_IdentityEnvVars_Snapshot(t *testing.T) {
	assert.Equal(t, []string{
		"SNYK_TOKEN",
		"SNYK_CFG_API",
		"SNYK_OAUTH_TOKEN",
		"SNYK_DOCKER_TOKEN",
		"INTERNAL_OAUTH_TOKEN_STORAGE",
		"INTERNAL_MACHINE_IDENTITY_STORAGE",
		"INTERNAL_NEW_SNYK_TOKEN",
	}, IdentityEnvVars())
}

func Test_IgnoreIdentityEnvVarsForProfile(t *testing.T) {
	t.Setenv("SNYK_TOKEN", "from-env")

	config := configuration.NewWithOpts(configuration.WithSupportedEnvVarPrefixes("snyk_", "internal_"))
	require.NoError(t, IgnoreIdentityEnvVarsForProfile("work", config))

	assert.Equal(t, IdentityEnvVars(), configuration.GetIgnoredEnvVars(config))
	assert.True(t, profile.IsProfile(config))
	assert.Equal(t, "work", profile.Name(config))
	assert.Empty(t, config.GetString(configuration.AUTHENTICATION_TOKEN))
}

// tenantEnvAncestorExclusions are environment-typed TENANT ancestors that are not identity
// credentials: API endpoint, organization selection, and the OAuth feature flag.
var tenantEnvAncestorExclusions = []string{
	configuration.API_URL,
	configuration.ORGANIZATION,
	configuration.FF_OAUTH_AUTH_FLOW_ENABLED,
}

func Test_IdentityEnvVars_CoverTenantEnvAncestors(t *testing.T) {
	config := configuration.NewWithOpts(
		configuration.WithSupportedEnvVarPrefixes("snyk_", "internal_"),
	)
	// Match the alternative keys hosts register next to auth/token wiring.
	config.AddAlternativeKeys(configuration.AUTHENTICATION_TOKEN, []string{"snyk_cfg_api", "api"})
	config.AddAlternativeKeys(configuration.AUTHENTICATION_BEARER_TOKEN, []string{"snyk_docker_token"})
	config.AddAlternativeKeys(configuration.API_URL, []string{"endpoint"})
	config.AddAlternativeKeys(configuration.ORGANIZATION, []string{"snyk_cfg_org"})

	engine := CreateAppEngineWithOptions(WithConfiguration(config), WithLogger(log.New(io.Discard, "", 0)))
	require.NotNil(t, engine)

	ancestors := configuration.KeyDependencies(config, configuration.TENANT)
	require.NotEmpty(t, ancestors)

	for _, ancestor := range ancestors {
		if config.GetKeyType(ancestor) != configuration.EnvVarKeyType {
			continue
		}
		if slices.Contains(tenantEnvAncestorExclusions, ancestor) {
			continue
		}
		assert.Truef(t, identityEnvContains(ancestor),
			"environment-typed TENANT ancestor %q must be in IdentityEnvVars or an explicit exclusion", ancestor)
	}
}

func identityEnvContains(key string) bool {
	for _, name := range IdentityEnvVars() {
		if strings.EqualFold(name, key) {
			return true
		}
	}
	return false
}
