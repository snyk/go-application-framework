package profile

import (
	"errors"
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
	// The marker key avoids the snyk_ and internal_ prefixes that hosts typically support.
	t.Setenv("GAF_CONFIG_PROFILE_MARKER", "from-env")

	config := configuration.NewWithOpts(
		configuration.WithSupportedEnvVarPrefixes("snyk_", "internal_"),
	)
	assert.False(t, IsProfile(config))
	assert.Equal(t, configuration.UnspecifiedKeyType, config.GetKeyType(markerKey))

	config.Set(markerKey, "work")
	assert.True(t, IsProfile(config))
	assert.Equal(t, "work", Name(config))
}

func Test_WithConfigEnrichment(t *testing.T) {
	t.Run("runs for named profiles after derive", func(t *testing.T) {
		dir := t.TempDir()
		base := configuration.NewWithOpts(
			configuration.WithSupportedEnvVarPrefixes("snyk_"),
			configuration.WithPinnedFile(filepath.Join(t.TempDir(), "base.json")),
		)
		t.Setenv("SNYK_TOKEN", "from-env")

		var seenName string
		reg, err := NewFileRegistry(dir, base, WithConfigEnrichment(func(name string, config configuration.Configuration) error {
			seenName = name
			ev, ok := config.(interface{ SetIgnoredEnvVars(...string) })
			require.True(t, ok)
			ev.SetIgnoredEnvVars("SNYK_TOKEN")
			return nil
		}))
		require.NoError(t, err)

		writeProfile(t, dir, "work", `{}`)
		p, err := reg.Profile("work")
		require.NoError(t, err)

		assert.Equal(t, "work", seenName)
		assert.True(t, IsProfile(p.Configuration()))
		assert.Empty(t, p.Configuration().GetString("snyk_token"))
		assert.Equal(t, []string{"SNYK_TOKEN"}, configuration.GetIgnoredEnvVars(p.Configuration()))
	})

	t.Run("does not run for the default profile", func(t *testing.T) {
		called := false
		reg, err := NewFileRegistry(t.TempDir(), configuration.NewWithOpts(), WithConfigEnrichment(func(string, configuration.Configuration) error {
			called = true
			return nil
		}))
		require.NoError(t, err)

		_, err = reg.Profile(DefaultName)
		require.NoError(t, err)
		assert.False(t, called)
	})

	t.Run("enrichment error makes the profile unavailable", func(t *testing.T) {
		reg, err := NewFileRegistry(t.TempDir(), configuration.NewWithOpts(), WithConfigEnrichment(func(string, configuration.Configuration) error {
			return errors.New("enrichment failed")
		}))
		require.NoError(t, err)

		_, err = reg.Profile("work")
		assertCatalogError(t, err, codeUnavailable, `Profile "work" cannot be loaded: enrichment failed.`)
	})
}
