package app

import (
	"io"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// The default functions resolve against the configuration they are called on. These tests use a plain engine,
// without profiles, and a clone with its own values, which is what workflows work on.
func Test_DefaultFunctionsFollowTheConfigurationTheyAreResolvedOn(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	base := configuration.NewWithOpts()
	engine := CreateAppEngineWithOptions(WithConfiguration(base), WithLogger(log.New(io.Discard, "", 0)))
	require.NoError(t, engine.Init())

	t.Run("IS_FEDRAMP follows the API_URL of the clone", func(t *testing.T) {
		clone := base.Clone()
		clone.Set(configuration.API_URL, "https://api.snykgov.io")
		assert.True(t, clone.GetBool(configuration.IS_FEDRAMP))
		assert.False(t, base.GetBool(configuration.IS_FEDRAMP))
	})

	t.Run("TEMP_DIR_PATH follows the CACHE_PATH of the clone", func(t *testing.T) {
		cache := filepath.Join(t.TempDir(), "clone-cache")
		clone := base.Clone()
		clone.Set(configuration.CACHE_PATH, cache)
		assert.True(t, strings.HasPrefix(clone.GetString(configuration.TEMP_DIR_PATH), cache))
		assert.False(t, strings.HasPrefix(base.GetString(configuration.TEMP_DIR_PATH), cache))
	})

	t.Run("custom config files follow the configfile of the clone", func(t *testing.T) {
		clone := base.Clone()
		clone.Set("configfile", "/some/where/custom.env")
		assert.Contains(t, clone.GetStringSlice(configuration.CUSTOM_CONFIG_FILES), "/some/where/custom.env")
		assert.NotContains(t, base.GetStringSlice(configuration.CUSTOM_CONFIG_FILES), "/some/where/custom.env")
	})
}

// The parent resolves the values first, so they are cached; a clone must not return the parent's cached values.
func Test_DefaultFunctionsFollowTheConfigurationTheyAreResolvedOnWhenCached(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	base := configuration.NewWithOpts(configuration.WithCachingEnabled(time.Hour))
	engine := CreateAppEngineWithOptions(WithConfiguration(base), WithLogger(log.New(io.Discard, "", 0)))
	require.NoError(t, engine.Init())

	_ = base.GetString(configuration.TEMP_DIR_PATH)
	_ = base.GetStringSlice(configuration.CUSTOM_CONFIG_FILES)
	_ = base.GetBool(configuration.IS_FEDRAMP)

	t.Run("TEMP_DIR_PATH follows the CACHE_PATH of the clone", func(t *testing.T) {
		cache := filepath.Join(t.TempDir(), "clone-cache")
		clone := base.Clone()
		clone.Set(configuration.CACHE_PATH, cache)
		assert.True(t, strings.HasPrefix(clone.GetString(configuration.TEMP_DIR_PATH), cache))
	})

	t.Run("custom config files follow the configfile of the clone", func(t *testing.T) {
		clone := base.Clone()
		clone.Set("configfile", "/some/where/custom.env")
		assert.Contains(t, clone.GetStringSlice(configuration.CUSTOM_CONFIG_FILES), "/some/where/custom.env")
	})

	t.Run("IS_FEDRAMP follows the API_URL of the clone", func(t *testing.T) {
		clone := base.Clone()
		clone.Set(configuration.API_URL, "https://api.snykgov.io")
		assert.True(t, clone.GetBool(configuration.IS_FEDRAMP))
		assert.False(t, base.GetBool(configuration.IS_FEDRAMP))
	})
}

func Test_DefaultFunctionsKeepExplicitValuesOfTheClone(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	base := configuration.NewWithOpts(configuration.WithCachingEnabled(time.Hour))
	engine := CreateAppEngineWithOptions(WithConfiguration(base), WithLogger(log.New(io.Discard, "", 0)))
	require.NoError(t, engine.Init())
	_ = base.GetBool(configuration.IS_FEDRAMP)
	_ = base.GetStringSlice(configuration.CUSTOM_CONFIG_FILES)

	t.Run("an explicit IS_FEDRAMP=false stays false on a snykgov API_URL", func(t *testing.T) {
		clone := base.Clone()
		clone.Set(configuration.API_URL, "https://api.snykgov.io")
		clone.Set(configuration.IS_FEDRAMP, false)
		assert.False(t, clone.GetBool(configuration.IS_FEDRAMP))
	})

	t.Run("an empty configfile adds no entry", func(t *testing.T) {
		clone := base.Clone()
		clone.Set("configfile", "")
		assert.Equal(t, base.GetStringSlice(configuration.CUSTOM_CONFIG_FILES), clone.GetStringSlice(configuration.CUSTOM_CONFIG_FILES))
		assert.NotContains(t, clone.GetStringSlice(configuration.CUSTOM_CONFIG_FILES), "")
	})
}
