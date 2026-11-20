package env_utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/profile"
)

func Test_PrepareSnykBinaryEnvironment(t *testing.T) {
	t.Run("default profile leaves env unchanged", func(t *testing.T) {
		config := configuration.NewWithOpts()
		env := []string{"SNYK_TOKEN=keep", "PATH=/bin"}

		got := PrepareSnykBinaryEnvironment(env, config)

		assert.Equal(t, env, got)
		assert.NotSame(t, &env[0], &got[0], "must return a copy")
		assert.Equal(t, "SNYK_TOKEN=keep", env[0], "must not mutate the input")
	})

	t.Run("named profile sets profile and directory", func(t *testing.T) {
		config := configuration.NewWithOpts()
		profile.SetMarker(config, "work")
		config.Set(profile.DirKey, "/tmp/profiles")

		got := PrepareSnykBinaryEnvironment([]string{"SNYK_TOKEN=keep", "OTHER=1"}, config)

		assert.Contains(t, got, "SNYK_TOKEN=keep")
		assert.Contains(t, got, "OTHER=1")
		assert.Contains(t, got, "SNYK_CONFIG_PROFILE=work")
		assert.Contains(t, got, "SNYK_CONFIG_PROFILE_DIR=/tmp/profiles")
	})

	t.Run("overwrites existing profile variables", func(t *testing.T) {
		config := configuration.NewWithOpts()
		profile.SetMarker(config, "work")
		config.Set(profile.DirKey, "/new/dir")

		got := PrepareSnykBinaryEnvironment([]string{
			"SNYK_CONFIG_PROFILE=old",
			"SNYK_CONFIG_PROFILE_DIR=/old/dir",
			"SNYK_TOKEN=keep",
		}, config)

		require.Len(t, got, 3)
		assert.Equal(t, "SNYK_CONFIG_PROFILE=work", got[0])
		assert.Equal(t, "SNYK_CONFIG_PROFILE_DIR=/new/dir", got[1])
		assert.Equal(t, "SNYK_TOKEN=keep", got[2])
	})

	t.Run("nil config returns a copy of env", func(t *testing.T) {
		env := []string{"A=1"}
		got := PrepareSnykBinaryEnvironment(env, nil)
		assert.Equal(t, env, got)
		assert.NotSame(t, &env[0], &got[0])
	})

	t.Run("omits directory when unset", func(t *testing.T) {
		config := configuration.NewWithOpts()
		profile.SetMarker(config, "work")

		got := PrepareSnykBinaryEnvironment(nil, config)

		assert.Equal(t, []string{"SNYK_CONFIG_PROFILE=work"}, got)
	})
}
