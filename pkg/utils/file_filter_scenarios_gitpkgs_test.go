package utils

import (
	"testing"
	"time"
)

func init() {
	registerScenarioImplementation(scenarioImplementation{
		name: "git-pkgs",
		run: func(tb testing.TB, scanRoot string, opts scenarioOptions) []string {
			tb.Helper()

			return gitPkgsScan(scanRoot, opts.ReadParentRuleFiles)
		},
	})
}

// BenchmarkGitPkgsScenarioWorkloadsCPU adds CPU time per run to the scenario workloads, which
// BenchmarkScenarioWorkloads shows only as wall time. Each tree is built before its timed loop.
func BenchmarkGitPkgsScenarioWorkloadsCPU(b *testing.B) {
	builders := []func(*testing.B) benchmarkWorkload{
		buildIgnoredNodeModulesWorkload,
		buildNestedRulesWorkload,
		buildFlatWorkload,
	}

	for _, build := range builders {
		workload := build(b)
		for _, impl := range scenarioImplementations {
			b.Run(impl.name+"/"+workload.name, func(b *testing.B) {
				b.ReportAllocs()

				var returned int
				cpuBefore := processCPUTime(b)
				b.ResetTimer()
				for range b.N {
					returned = len(impl.run(b, workload.root, scenarioOptions{}))
				}
				b.StopTimer()
				cpu := processCPUTime(b) - cpuBefore

				b.ReportMetric(float64(cpu)/float64(time.Millisecond)/float64(b.N), "cpu-ms/op")
				b.ReportMetric(float64(returned), "files")
				if returned != workload.wantFiles {
					b.Errorf("%s/%s returned %d files, want %d", impl.name, workload.name, returned, workload.wantFiles)
				}
			})
		}
	}
}
