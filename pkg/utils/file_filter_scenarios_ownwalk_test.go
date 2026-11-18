package utils

import (
	"testing"
)

func init() {
	registerScenarioImplementation(scenarioImplementation{
		name: "own-walk",
		run: func(tb testing.TB, scanRoot string, opts scenarioOptions) []string {
			tb.Helper()

			return ownWalkScan(scanRoot, opts.ReadParentRuleFiles)
		},
	})
}
