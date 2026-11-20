package app

import (
	"io"
	"log"
	"strings"
	"testing"

	snyk_errors "github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/machinecredential"
	"github.com/snyk/go-application-framework/pkg/auth"
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
	t.Run("sets marker only", func(t *testing.T) {
		config := configuration.NewWithOpts(configuration.WithSupportedEnvVarPrefixes("snyk_", "internal_"))
		require.NoError(t, IgnoreIdentityEnvVarsForProfile("work", config))

		assert.Empty(t, configuration.GetIgnoredEnvVars(config), "ignores belong in IdentityIgnoreDeriveOpts")
		assert.True(t, profile.IsProfile(config))
		assert.Equal(t, "work", profile.Name(config))
	})

	t.Run("nil config is a no-op", func(t *testing.T) {
		require.NoError(t, IgnoreIdentityEnvVarsForProfile("work", nil))
	})
}

func Test_IdentityIgnoreDeriveOpts_AppliedAtDerive(t *testing.T) {
	t.Setenv("SNYK_TOKEN", "ambient")

	dir := t.TempDir()
	base := configuration.NewWithOpts(
		configuration.WithSupportedEnvVarPrefixes("snyk_", "internal_"),
	)
	reg, err := profile.NewFileRegistry(dir, base,
		profile.WithDeriveOpts(IdentityIgnoreDeriveOpts()...),
		profile.WithConfigEnrichment(IgnoreIdentityEnvVarsForProfile),
	)
	require.NoError(t, err)

	p, err := reg.Profile("work")
	require.NoError(t, err)

	cfg := p.Configuration()
	assert.True(t, profile.IsProfile(cfg))
	assert.Equal(t, IdentityEnvVars(), configuration.GetIgnoredEnvVars(cfg))
	assert.Empty(t, cfg.GetString(configuration.AUTHENTICATION_TOKEN))
	assert.Empty(t, cfg.GetString("snyk_token"))
}

func Test_IdentityIgnoreDeriveOpts_FailsWithAutomaticEnv(t *testing.T) {
	dir := t.TempDir()
	base := configuration.NewWithOpts(
		configuration.WithAutomaticEnv(),
		configuration.WithSupportedEnvVarPrefixes("snyk_"),
	)
	reg, err := profile.NewFileRegistry(dir, base, profile.WithDeriveOpts(IdentityIgnoreDeriveOpts()...))
	require.NoError(t, err)

	_, err = reg.Profile("work")
	require.Error(t, err)
	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr)
	assert.Equal(t, "SNYK-CLI-0037", catalogErr.ErrorCode)
	assert.Equal(t, `Profile "work" cannot be loaded.`, catalogErr.Detail)
}

// tenantCredentialAncestors are the credential-related keys that defaultFuncTenantId depends on.
// API_URL, ORGANIZATION, and FF_OAUTH_AUTH_FLOW_ENABLED are intentionally excluded: they are not
// identity credentials for named-profile isolation.
var tenantCredentialAncestors = []string{
	configuration.AUTHENTICATION_TOKEN,
	configuration.AUTHENTICATION_BEARER_TOKEN,
	auth.CONFIG_KEY_OAUTH_TOKEN,
	machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE,
}

func Test_IdentityEnvVars_CoverTenantCredentialAncestors(t *testing.T) {
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

	for _, ancestor := range tenantCredentialAncestors {
		assert.Truef(t, identityEnvContains(ancestor),
			"TENANT credential ancestor %q must be covered by IdentityEnvVars", ancestor)
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
