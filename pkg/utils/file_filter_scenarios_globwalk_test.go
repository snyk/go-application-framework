package utils

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func init() {
	registerScenarioImplementation(scenarioImplementation{
		name: "glob-walk",
		// Keeps today's rule translation, so the known gaps of current hold for this variant too.
		sharesCurrentGaps: true,
		// Parent rule files are not supported, so opts is ignored.
		run: func(tb testing.TB, scanRoot string, _ scenarioOptions) []string {
			tb.Helper()

			config := newTestConfig(map[string]bool{
				FF_GITIGNORE_RESPECT_TRACKED_FILES: true,
				FF_FILE_FILTER_METACHARACTER_FIX:   false,
			})
			logger := zerolog.Nop()
			fileFilter := NewFileFilter(scanRoot, &logger, WithConfig(config))

			files, compiled := fileFilter.globWalkFiles(true)
			tb.Logf("glob-walk compiled %d matchers", compiled)

			return files
		},
	})
}

// BenchmarkGlobWalkScenarioWorkloadsCPU adds CPU time per run to the scenario workloads, which
// BenchmarkScenarioWorkloads shows only as wall time. Each tree is built before its timed loop.
func BenchmarkGlobWalkScenarioWorkloadsCPU(b *testing.B) {
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
