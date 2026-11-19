package utils

import (
	"testing"

	"github.com/rs/zerolog"
)

func init() {
	registerScenarioImplementation(scenarioImplementation{
		name: "gocodewalker",
		run: func(tb testing.TB, scanRoot string, opts scenarioOptions) []string {
			tb.Helper()

			logger := zerolog.Nop()

			return gocodewalkerScan(scanRoot, &logger)
		},
	})
}
