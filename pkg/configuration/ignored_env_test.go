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

		assert.Empty(t, clone.GetString("snyk_token"))
		assert.Equal(t, "from-env", NewWithOpts(WithSupportedEnvVarPrefixes("snyk_")).GetString("snyk_token"),
			"control: without ignore the env token is visible")
	})

	t.Run("WithIgnoredEnvVars is additive across options", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "from-env")
		t.Setenv("SNYK_OAUTH_TOKEN", "oauth-from-env")

		config := NewWithOpts(
			WithSupportedEnvVarPrefixes("snyk_"),
			WithIgnoredEnvVars("SNYK_TOKEN"),
			WithIgnoredEnvVars("SNYK_OAUTH_TOKEN"),
		)

		assert.Empty(t, config.GetString("snyk_token"))
		assert.Empty(t, config.GetString("snyk_oauth_token"))
	})

	t.Run("WithIgnoredEnvVars dedupes case-insensitively", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "from-env")

		config := NewWithOpts(
			WithSupportedEnvVarPrefixes("snyk_"),
			WithIgnoredEnvVars("SNYK_TOKEN"),
			WithIgnoredEnvVars("snyk_token"),
		)
		assert.Empty(t, config.GetString("snyk_token"))
	})

	t.Run("ignore matching normalizes hyphen to underscore", func(t *testing.T) {
		t.Setenv("SNYK_CFG_API", "from-env")

		config := NewWithOpts(
			WithSupportedEnvVarPrefixes("snyk_"),
			WithIgnoredEnvVars("SNYK_CFG_API"),
		)

		assert.Empty(t, config.GetString("snyk_cfg-api"))
		assert.Empty(t, config.GetAllKeysThatContainValues("snyk_cfg-api"))
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

		assert.Empty(t, derived.GetString("snyk_token"))
		assert.Empty(t, derived.GetString("snyk_oauth_token"))
		assert.Equal(t, "https://api.example", derived.GetString("snyk_api"))
	})

	t.Run("two WithIgnoredEnvVars options in one Derive keep both", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "from-env")
		t.Setenv("SNYK_OAUTH_TOKEN", "oauth-from-env")

		base := NewWithOpts(
			WithSupportedEnvVarPrefixes("snyk_"),
			WithPinnedFile(filepath.Join(t.TempDir(), "base.json")),
		)
		derived, err := Derive(base,
			WithPinnedFile(filepath.Join(t.TempDir(), "derived.json")),
			WithIgnoredEnvVars("SNYK_TOKEN"),
			WithIgnoredEnvVars("SNYK_OAUTH_TOKEN"),
		)
		require.NoError(t, err)

		assert.Empty(t, derived.GetString("snyk_token"))
		assert.Empty(t, derived.GetString("snyk_oauth_token"))
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
			_ = config.GetAllKeysThatContainValues("snyk_token")
			_ = config.Clone()
		}()
	}
	wg.Wait()

	assert.Empty(t, config.GetString("snyk_token"))
	assert.Equal(t, "https://api.example", config.GetString("snyk_api"))
}

func Test_WithIgnoredEnvVars_ForeignConfigurationIsIgnored(t *testing.T) {
	foreign := struct{ Configuration }{}
	assert.NotPanics(t, func() { WithIgnoredEnvVars("SNYK_TOKEN")(foreign) })
	assert.Empty(t, ignoredEnvVarsOf(foreign))
}

// foreignConfig is a Configuration that this package did not create.
type foreignConfig struct{ Configuration }

func Test_IgnoredEnvVarsThatAreSet(t *testing.T) {
	t.Run("reports the ignored names that are set to a non-empty value", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "secret")
		t.Setenv("SNYK_API", "https://api.example")

		config := NewWithOpts(
			WithSupportedEnvVarPrefixes("snyk_"),
			WithIgnoredEnvVars("SNYK_TOKEN", "SNYK_OAUTH_TOKEN"),
		)

		assert.Equal(t, []string{"SNYK_TOKEN"}, IgnoredEnvVarsThatAreSet(config))
	})

	t.Run("an empty value is not reported", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "")

		config := NewWithOpts(
			WithSupportedEnvVarPrefixes("snyk_"),
			WithIgnoredEnvVars("SNYK_TOKEN"),
		)

		assert.Nil(t, IgnoredEnvVarsThatAreSet(config))
	})

	t.Run("no ignored names reports nothing", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "secret")

		assert.Nil(t, IgnoredEnvVarsThatAreSet(NewWithOpts(WithSupportedEnvVarPrefixes("snyk_"))))
	})

	t.Run("a foreign configuration reports nothing", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "secret")

		assert.Nil(t, IgnoredEnvVarsThatAreSet(foreignConfig{}))
		assert.Nil(t, IgnoredEnvVarsThatAreSet(nil))
	})

	t.Run("matches case-insensitively with hyphens and underscores equivalent, and reports the recorded spelling", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "secret")
		t.Setenv("snyk_oauth_token", "secret")

		config := NewWithOpts(
			WithSupportedEnvVarPrefixes("snyk_"),
			WithIgnoredEnvVars("snyk-token", "SNYK_OAUTH_TOKEN"),
		)

		assert.Equal(t, []string{"snyk-token", "SNYK_OAUTH_TOKEN"}, IgnoredEnvVarsThatAreSet(config))
	})

	t.Run("reports in recorded order", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "secret")
		t.Setenv("SNYK_OAUTH_TOKEN", "secret")

		config := NewWithOpts(
			WithSupportedEnvVarPrefixes("snyk_"),
			WithIgnoredEnvVars("SNYK_OAUTH_TOKEN", "SNYK_TOKEN"),
		)

		assert.Equal(t, []string{"SNYK_OAUTH_TOKEN", "SNYK_TOKEN"}, IgnoredEnvVarsThatAreSet(config))
	})
}
