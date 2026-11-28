package config_utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/profile"
)

func Test_CheckIgnoredEnvVars(t *testing.T) {
	t.Run("reports one result that names only the ignored variables that are set", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "secret")
		t.Setenv("SNYK_API", "https://api.example")

		config := configuration.NewWithOpts(
			configuration.WithSupportedEnvVarPrefixes("snyk_"),
			configuration.WithIgnoredEnvVars("SNYK_TOKEN", "SNYK_OAUTH_TOKEN"),
		)

		result := CheckIgnoredEnvVars(config)
		require.Len(t, result, 1)
		assert.Equal(t, "When using configuration profiles, the following environment variable(s) are not used SNYK_TOKEN", result[0].Description)
		assert.NotContains(t, result[0].Description, "secret")
	})

	t.Run("lists several names uppercase, comma separated", func(t *testing.T) {
		t.Setenv("snyk-token", "secret")
		t.Setenv("SNYK_OAUTH_TOKEN", "secret")

		config := configuration.NewWithOpts(
			configuration.WithSupportedEnvVarPrefixes("snyk_"),
			configuration.WithIgnoredEnvVars("snyk-token", "SNYK_OAUTH_TOKEN"),
		)

		result := CheckIgnoredEnvVars(config)
		require.Len(t, result, 1)
		assert.Equal(t, "When using configuration profiles, the following environment variable(s) are not used SNYK-TOKEN, SNYK_OAUTH_TOKEN", result[0].Description)
	})

	t.Run("an empty value reports nothing", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "")

		config := configuration.NewWithOpts(
			configuration.WithSupportedEnvVarPrefixes("snyk_"),
			configuration.WithIgnoredEnvVars("SNYK_TOKEN"),
		)

		assert.Empty(t, CheckIgnoredEnvVars(config))
	})

	t.Run("no ignored names reports nothing", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "secret")

		assert.Empty(t, CheckIgnoredEnvVars(configuration.NewWithOpts(configuration.WithSupportedEnvVarPrefixes("snyk_"))))
	})

	t.Run("CheckSanity includes the result", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "secret")

		config := configuration.NewWithOpts(
			configuration.WithSupportedEnvVarPrefixes("snyk_"),
			configuration.WithIgnoredEnvVars("SNYK_TOKEN"),
		)

		assert.Contains(t, CheckSanity(config), SanityCheckResult{
			Description: "When using configuration profiles, the following environment variable(s) are not used SNYK_TOKEN",
		})
	})

	t.Run("a named profile that ignores a variable reports it, the default profile does not", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "secret")

		base := configuration.NewWithOpts(configuration.WithSupportedEnvVarPrefixes("snyk_"))
		registry, err := profile.NewFileRegistry(t.TempDir(), base)
		require.NoError(t, err)
		require.NoError(t, registry.SetIgnoredEnvVars("SNYK_TOKEN"))

		work, err := registry.Profile("work")
		require.NoError(t, err)
		assert.Equal(t, []SanityCheckResult{{
			Description: "When using configuration profiles, the following environment variable(s) are not used SNYK_TOKEN",
		}}, CheckIgnoredEnvVars(work.Configuration()))

		def, err := registry.Profile(profile.DefaultName)
		require.NoError(t, err)
		assert.Empty(t, CheckIgnoredEnvVars(def.Configuration()))
	})
}
