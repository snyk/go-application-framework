package configuration

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_WithIgnoredEnvVars(t *testing.T) {
	t.Run("ignored name is not read even when supported", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "from-env")
		t.Setenv("SNYK_API", "https://api.example")

		config := NewWithOpts(
			WithSupportedEnvVarPrefixes("snyk_"),
			WithIgnoredEnvVars("SNYK_TOKEN"),
		)

		assert.Empty(t, config.GetString("snyk_token"))
		assert.Equal(t, "https://api.example", config.GetString("snyk_api"))
		assert.Equal(t, EnvVarKeyType, config.GetKeyType("snyk_token"), "GetKeyType must not change for ignored names")
		assert.Equal(t, []string{"SNYK_TOKEN"}, GetIgnoredEnvVars(config))
	})

	t.Run("matching is case-insensitive", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "from-env")

		config := NewWithOpts(
			WithSupportedEnvVarPrefixes("snyk_"),
			WithIgnoredEnvVars("snyk_token"),
		)

		assert.Empty(t, config.GetString("SNYK_TOKEN"))
		assert.Empty(t, config.GetAllKeysThatContainValues("snyk_token"))
	})

	t.Run("ignored name wins over an explicitly supported env var", func(t *testing.T) {
		t.Setenv("NODE_EXTRA_CA_CERTS", "/certs")

		config := NewWithOpts(
			WithSupportedEnvVars("NODE_EXTRA_CA_CERTS"),
			WithIgnoredEnvVars("NODE_EXTRA_CA_CERTS"),
		)

		assert.Empty(t, config.GetString("NODE_EXTRA_CA_CERTS"))
		assert.Empty(t, config.GetAllKeysThatContainValues("NODE_EXTRA_CA_CERTS"))
	})

	t.Run("GetAllKeysThatContainValues skips ignored env vars that are set", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "from-env")
		t.Setenv("SNYK_API", "https://api.example")

		config := NewWithOpts(
			WithSupportedEnvVarPrefixes("snyk_"),
			WithIgnoredEnvVars("SNYK_TOKEN"),
		)
		config.AddAlternativeKeys(AUTHENTICATION_TOKEN, []string{"snyk_token"})

		assert.Empty(t, config.GetAllKeysThatContainValues(AUTHENTICATION_TOKEN))
		assert.Equal(t, []string{"snyk_api"}, config.GetAllKeysThatContainValues(API_URL))
	})

	t.Run("Clone copies the ignored set", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "from-env")

		config := NewWithOpts(
			WithSupportedEnvVarPrefixes("snyk_"),
			WithIgnoredEnvVars("SNYK_TOKEN"),
		)
		clone := config.Clone()

		assert.Equal(t, []string{"SNYK_TOKEN"}, GetIgnoredEnvVars(clone))
		assert.Empty(t, clone.GetString("snyk_token"))
	})

	t.Run("SetIgnoredEnvVars replaces the list", func(t *testing.T) {
		config := NewWithOpts(WithIgnoredEnvVars("A", "B"))
		asViper(t, config).SetIgnoredEnvVars("C")
		assert.Equal(t, []string{"C"}, GetIgnoredEnvVars(config))
	})

	t.Run("package getter returns nil for foreign configurations", func(t *testing.T) {
		assert.Nil(t, GetIgnoredEnvVars(foreignConfiguration{Configuration: NewWithOpts()}))
	})
}

func Test_Derive_IgnoredEnvVars(t *testing.T) {
	t.Run("copies ignored env vars from base and merges options", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "from-env")
		t.Setenv("SNYK_OAUTH_TOKEN", "oauth-from-env")
		t.Setenv("SNYK_API", "https://api.example")

		base := NewWithOpts(
			WithSupportedEnvVarPrefixes("snyk_"),
			WithIgnoredEnvVars("SNYK_TOKEN"),
			WithPinnedFile(filepath.Join(t.TempDir(), "base.json")),
		)
		derived, err := Derive(base,
			WithPinnedFile(filepath.Join(t.TempDir(), "derived.json")),
			WithIgnoredEnvVars("SNYK_OAUTH_TOKEN"),
		)
		require.NoError(t, err)

		assert.ElementsMatch(t, []string{"SNYK_OAUTH_TOKEN", "SNYK_TOKEN"}, GetIgnoredEnvVars(derived))
		assert.Empty(t, derived.GetString("snyk_token"))
		assert.Empty(t, derived.GetString("snyk_oauth_token"))
		assert.Equal(t, "https://api.example", derived.GetString("snyk_api"))
	})

	t.Run("errors when AutomaticEnv is enabled with ignored env vars from base", func(t *testing.T) {
		base := NewWithOpts(WithAutomaticEnv(), WithIgnoredEnvVars("SNYK_TOKEN"))
		_, err := Derive(base)
		require.Error(t, err)
		assert.ErrorContains(t, err, "AutomaticEnv is incompatible with ignored environment variables")
	})

	t.Run("errors when AutomaticEnv is enabled with ignored env vars from opts", func(t *testing.T) {
		base := NewWithOpts(WithAutomaticEnv())
		_, err := Derive(base, WithIgnoredEnvVars("SNYK_TOKEN"))
		require.Error(t, err)
		assert.ErrorContains(t, err, "AutomaticEnv is incompatible with ignored environment variables")
	})

	t.Run("errors when AutomaticEnv comes from opts and ignored from base", func(t *testing.T) {
		base := NewWithOpts(WithIgnoredEnvVars("SNYK_TOKEN"))
		_, err := Derive(base, WithAutomaticEnv())
		require.Error(t, err)
		assert.ErrorContains(t, err, "AutomaticEnv is incompatible with ignored environment variables")
	})
}

func Test_IgnoredEnvVars_ConcurrentAccess(t *testing.T) {
	config := NewWithOpts(
		WithSupportedEnvVarPrefixes("snyk_"),
		WithIgnoredEnvVars("SNYK_TOKEN"),
	)
	t.Setenv("SNYK_TOKEN", "from-env")
	t.Setenv("SNYK_API", "https://api.example")

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = config.GetString("snyk_token")
			_ = config.GetString("snyk_api")
			_ = GetIgnoredEnvVars(config)
			_ = config.GetAllKeysThatContainValues("snyk_token")
			_ = config.Clone()
		}()
	}
	wg.Wait()

	assert.Empty(t, config.GetString("snyk_token"))
	assert.Equal(t, "https://api.example", config.GetString("snyk_api"))
}

func Test_KeyDependencies(t *testing.T) {
	config := NewWithOpts()
	require.NoError(t, config.AddKeyDependency("child", "parent"))
	require.NoError(t, config.AddKeyDependency("child", "other"))
	require.NoError(t, config.AddKeyDependency("grandchild", "child"))

	assert.ElementsMatch(t, []string{"parent", "other"}, KeyDependencies(config, "child"))
	assert.Equal(t, []string{"child"}, KeyDependencies(config, "grandchild"))
	assert.Empty(t, KeyDependencies(config, "parent"))
	assert.Nil(t, KeyDependencies(foreignConfiguration{Configuration: config}, "child"))
}
