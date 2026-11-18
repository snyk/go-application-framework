package utils

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

var currentRuleFiles = []string{".gitignore", ".dcignore", ".snyk"}

var currentWithMetacharacterFix = scenarioImplementation{
	name: currentImplementationName + "+metacharacter-fix",
	run: func(tb testing.TB, scanRoot string, _ scenarioOptions) []string {
		tb.Helper()

		return runCurrentFileFilter(tb, scanRoot, true)
	},
}

func init() {
	registerScenarioImplementation(scenarioImplementation{
		name: currentImplementationName,
		// Parent rule files are not supported, so opts is ignored.
		run: func(tb testing.TB, scanRoot string, _ scenarioOptions) []string {
			tb.Helper()

			return runCurrentFileFilter(tb, scanRoot, false)
		},
	})
}

func runCurrentFileFilter(tb testing.TB, scanRoot string, metacharacterFix bool) []string {
	tb.Helper()

	config := newTestConfig(map[string]bool{
		FF_GITIGNORE_RESPECT_TRACKED_FILES: true,
		FF_FILE_FILTER_METACHARACTER_FIX:   metacharacterFix,
	})
	// A nop logger: the benchmark would otherwise pay for a debug line per scan.
	logger := zerolog.Nop()
	fileFilter := NewFileFilter(scanRoot, &logger, WithConfig(config))

	rules, err := fileFilter.GetRules(currentRuleFiles)
	require.NoError(tb, err)

	var files []string
	for file := range fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), rules) {
		files = append(files, file)
	}

	return files
}
