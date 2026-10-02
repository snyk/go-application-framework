package workflow

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils"
)

// TestInvocationContextImpl_GetFileFilter asserts GetFileFilter uses the invocation's configuration.
func TestInvocationContextImpl_GetFileFilter(t *testing.T) {
	// A .gitignore rule for a directory whose path contains regex metacharacters is only honored
	// when the metacharacter-fix feature flag is enabled, which makes it a usable probe for whether a
	// config reached the FileFilter.
	setup := func(t *testing.T) (base string, nodeModulesFile string) {
		t.Helper()
		base = filepath.Join(t.TempDir(), "OneDrive - Foobar (Team1)", "repo")
		nodeModulesFile = filepath.Join(base, "node_modules", "lib", "index.js")

		require.NoError(t, os.MkdirAll(filepath.Dir(nodeModulesFile), 0755))
		require.NoError(t, os.WriteFile(nodeModulesFile, []byte("x"), 0600))
		require.NoError(t, os.WriteFile(filepath.Join(base, ".gitignore"), []byte("node_modules\n"), 0600))

		return base, nodeModulesFile
	}

	filteredFiles := func(t *testing.T, fileFilter *utils.FileFilter) []string {
		t.Helper()
		globs, err := fileFilter.GetRules([]string{".gitignore"})
		require.NoError(t, err)

		var filtered []string
		for f := range fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), globs) {
			filtered = append(filtered, f)
		}
		return filtered
	}

	configWithFix := func(enabled bool) configuration.Configuration {
		config := configuration.NewWithOpts()
		config.Set(utils.FF_FILE_FILTER_METACHARACTER_FIX, enabled)
		return config
	}

	newContext := func(config configuration.Configuration) *invocationContextImpl {
		return &invocationContextImpl{Configuration: config, logger: &zerolog.Logger{}}
	}

	t.Run("resolves feature flags from the configuration of the invocation", func(t *testing.T) {
		base, nodeModulesFile := setup(t)

		ictx := newContext(configWithFix(true))
		assert.NotContains(t, filteredFiles(t, ictx.GetFileFilter(base)), nodeModulesFile,
			"flag on: node_modules must be excluded even though the base path has metacharacters")

		ictx = newContext(configWithFix(false))
		assert.Contains(t, filteredFiles(t, ictx.GetFileFilter(base)), nodeModulesFile,
			"flag off: the legacy behavior must be reproduced")
	})

	t.Run("caller options take precedence over the wiring", func(t *testing.T) {
		base, nodeModulesFile := setup(t)
		ictx := newContext(configWithFix(true))

		fileFilter := ictx.GetFileFilter(base, utils.WithConfig(configWithFix(false)))

		assert.Contains(t, filteredFiles(t, fileFilter), nodeModulesFile,
			"the option passed by the caller must win over the invocation's configuration")
	})

	fileFilterMetrics := func(t *testing.T, invocationAnalytics analytics.Analytics) map[string]any {
		t.Helper()

		obj, err := analytics.GetV2InstrumentationObject(invocationAnalytics.GetInstrumentation())
		require.NoError(t, err)

		recorded := map[string]any{}
		for key, value := range *obj.Data.Attributes.Interaction.Extension {
			if strings.HasPrefix(key, "file-filter.") {
				recorded[key] = value
			}
		}
		return recorded
	}

	t.Run("reports filter metrics through the analytics of the invocation", func(t *testing.T) {
		base, _ := setup(t)
		invocationAnalytics := analytics.New()
		ictx := &invocationContextImpl{
			Configuration: configuration.NewWithOpts(),
			logger:        &zerolog.Logger{},
			Analytics:     invocationAnalytics,
		}

		filteredFiles(t, ictx.GetFileFilter(base))

		assert.ElementsMatch(t, []string{
			"file-filter.var0.filter.inputFileCount",
			"file-filter.var0.filter.durationMs",
			"file-filter.var0.rules.durationMs",
			"file-filter.var0.filter.outputFileCount",
			"file-filter.var0.feature.metaCharFix",
			"file-filter.var0.feature.includeTracked",
		}, slices.Collect(maps.Keys(fileFilterMetrics(t, invocationAnalytics))))
	})
}
