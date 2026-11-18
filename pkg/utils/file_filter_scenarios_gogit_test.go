package utils

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func init() {
	registerScenarioImplementation(scenarioImplementation{
		name: "go-git-v6",
		run: func(tb testing.TB, scanRoot string, opts scenarioOptions) []string {
			tb.Helper()

			logger := zerolog.Nop()
			files, err := goGitFilter(scanRoot, &logger, goGitFilterOptions(opts))
			require.NoError(tb, err)

			return files
		},
	})
}
