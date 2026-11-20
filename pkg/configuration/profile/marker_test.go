package profile

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_IsProfile_DefaultHasNoMarker(t *testing.T) {
	env := newTestRegistry(t)
	p, err := env.reg.Profile(DefaultName)
	require.NoError(t, err)

	assert.False(t, IsProfile(p.Configuration()))
	assert.Empty(t, Name(p.Configuration()))
	assert.False(t, IsProfile(nil))
	assert.Empty(t, Name(nil))
}

func Test_IsProfile_NamedProfileSetsMarker(t *testing.T) {
	env := newTestRegistry(t)
	writeProfile(t, env.dir, "work", `{"token":"profile-token"}`)

	p, err := env.reg.Profile("work")
	require.NoError(t, err)

	assert.True(t, IsProfile(p.Configuration()))
	assert.Equal(t, "work", Name(p.Configuration()))
}

func Test_IsProfile_CloneKeepsMarker(t *testing.T) {
	env := newTestRegistry(t)
	writeProfile(t, env.dir, "work", `{}`)

	p, err := env.reg.Profile("work")
	require.NoError(t, err)

	clone := p.Configuration().Clone()
	assert.True(t, IsProfile(clone))
	assert.Equal(t, "work", Name(clone))
}

func Test_IsProfile_MarkerIgnoresEnvironment(t *testing.T) {
	// The profile name key avoids the snyk_ and internal_ prefixes that hosts typically support.
	t.Setenv("GAF_CONFIG_PROFILE_NAME", "from-env")

	config := configuration.NewWithOpts(
		configuration.WithSupportedEnvVarPrefixes("snyk_", "internal_"),
	)
	assert.False(t, IsProfile(config))
	assert.Equal(t, configuration.UnspecifiedKeyType, config.GetKeyType(profileNameKey))

	config.Set(profileNameKey, "work")
	assert.True(t, IsProfile(config))
	assert.Equal(t, "work", Name(config))
}

func Test_SetIgnoredEnvVars(t *testing.T) {
	t.Run("applies ignored env vars at Derive before any read", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "ambient")

		dir := t.TempDir()
		base := configuration.NewWithOpts(
			configuration.WithSupportedEnvVarPrefixes("snyk_"),
			configuration.WithPinnedFile(filepath.Join(t.TempDir(), "base.json")),
		)
		SetIgnoredEnvVars(base, "SNYK_TOKEN")
		reg, err := NewFileRegistry(dir, base)
		require.NoError(t, err)

		writeProfile(t, dir, "work", `{}`)
		p, err := reg.Profile("work")
		require.NoError(t, err)

		cfg := p.Configuration()
		assert.Empty(t, cfg.GetString("snyk_token"))
		assert.True(t, IsProfile(cfg))
	})

	t.Run("does not apply to base or the default profile", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "ambient")

		base := configuration.NewWithOpts(configuration.WithSupportedEnvVarPrefixes("snyk_"))
		SetIgnoredEnvVars(base, "SNYK_TOKEN")
		reg, err := NewFileRegistry(t.TempDir(), base)
		require.NoError(t, err)

		p, err := reg.Profile(DefaultName)
		require.NoError(t, err)
		assert.Equal(t, "ambient", p.Configuration().GetString("snyk_token"))
		assert.Equal(t, "ambient", base.GetString("snyk_token"))
	})

	t.Run("is read on every first load, and clearing removes the names", func(t *testing.T) {
		t.Setenv("SNYK_TOKEN", "ambient")

		dir := t.TempDir()
		base := configuration.NewWithOpts(configuration.WithSupportedEnvVarPrefixes("snyk_"))
		reg, err := NewFileRegistry(dir, base)
		require.NoError(t, err)

		SetIgnoredEnvVars(base, "SNYK_TOKEN")
		p, err := reg.Profile("one")
		require.NoError(t, err)
		assert.Empty(t, p.Configuration().GetString("snyk_token"))

		SetIgnoredEnvVars(base)
		p, err = reg.Profile("two")
		require.NoError(t, err)
		assert.Equal(t, "ambient", p.Configuration().GetString("snyk_token"))
	})

	t.Run("is not read from the environment", func(t *testing.T) {
		t.Setenv("GAF_PROFILE_IGNORED_ENV_VARS", "SNYK_TOKEN")
		base := configuration.NewWithOpts(configuration.WithSupportedEnvVarPrefixes("snyk_", "internal_"))
		assert.Empty(t, ignoredEnvVarsOf(base))
	})

	t.Run("is nil safe", func(t *testing.T) {
		assert.NotPanics(t, func() { SetIgnoredEnvVars(nil, "SNYK_TOKEN") })
		assert.Empty(t, ignoredEnvVarsOf(nil))
	})

	t.Run("AutomaticEnv with ignored names makes the profile unavailable", func(t *testing.T) {
		base := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		SetIgnoredEnvVars(base, "SNYK_TOKEN")
		reg, err := NewFileRegistry(t.TempDir(), base)
		require.NoError(t, err)

		_, err = reg.Profile("work")
		assertCatalogError(t, err, codeUnavailable, `Profile "work" cannot be loaded.`)
	})
}
