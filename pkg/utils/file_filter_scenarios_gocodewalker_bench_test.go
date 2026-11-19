//go:build unix

package utils

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The gocodewalker implementation registers itself in file_filter_scenarios_gocodewalker_test.go,
// so BenchmarkScenarioWorkloads and the BenchmarkRealistic* benchmarks already run it next to the
// other implementations. This file adds what those lack: CPU time on the three scenario workloads,
// and a split of the realistic workloads into the library's own walk and the adapter's extra work.
//
//	go test ./pkg/utils -run '^$' -bench '^BenchmarkScenarioWorkloadsWithCPU$' -benchmem -benchtime=3x -v
//	go test ./pkg/utils -run '^$' -bench '^BenchmarkGocodewalkerSplitTree225k31kRules$' -benchmem -benchtime=3x -v

// BenchmarkScenarioWorkloadsWithCPU is BenchmarkScenarioWorkloads plus cpu-ms/op.
func BenchmarkScenarioWorkloadsWithCPU(b *testing.B) {
	workloads := []benchmarkWorkload{
		buildIgnoredNodeModulesWorkload(b),
		buildNestedRulesWorkload(b),
		buildFlatWorkload(b),
	}
	logCoreLimit(b)

	for _, impl := range scenarioImplementations {
		for _, workload := range workloads {
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

func BenchmarkGocodewalkerSplitTracked200kFlat(b *testing.B) {
	runGocodewalkerSplit(b, "tracked-200k-flat", populateTracked200kFlat)
}

func BenchmarkGocodewalkerSplitTree225k36kRules(b *testing.B) {
	runGocodewalkerSplit(b, "tree-225k-3.6k-rules", populateTree225k36kRules)
}

func BenchmarkGocodewalkerSplitTree225k31kRules(b *testing.B) {
	runGocodewalkerSplit(b, "tree-225k-31k-rules", populateTree225k31kRules)
}

func BenchmarkGocodewalkerSplitMonorepoNodeModules(b *testing.B) {
	runGocodewalkerSplit(b, "monorepo-node-modules", populateMonorepoNodeModules)
}

// runGocodewalkerSplit times three nested stages on one workload: the library's walk alone (its
// file count differs from git's, because tracked files in ignored folders, symlinks and .git
// entries are the adapter's job), the walk plus the adapter's lstat of every result, and the full
// adapter.
func runGocodewalkerSplit(b *testing.B, name string, populate func(testing.TB, *fixture)) {
	b.Helper()

	isolateGit(b)

	root, err := os.MkdirTemp("", "cli2075-gocodewalker-"+name+"-")
	require.NoError(b, err)
	b.Cleanup(func() { _ = os.RemoveAll(root) })

	logCoreLimit(b)

	fx := &fixture{root: root}
	populate(b, fx)
	fx.commit(b)
	waitForGitIdle(b, root)
	wantFiles := oracleCount(b, root)

	stages := []struct {
		name string
		run  func() int
		// exact means the stage must return what git lists.
		exact bool
	}{
		{"library-walk-only", func() int { return len(rawGocodewalker(root, true)) }, false},
		{"walk-plus-lstat", func() int { return len(gocodewalkerWalk(root, nopLogger())) }, false},
		{"full-adapter", func() int { return len(gocodewalkerScan(root, nopLogger())) }, true},
	}

	for _, stage := range stages {
		b.Run(stage.name, func(b *testing.B) {
			b.ReportAllocs()

			var returned int
			cpuBefore := processCPUTime(b)
			b.ResetTimer()
			for range b.N {
				returned = stage.run()
			}
			b.StopTimer()
			cpu := processCPUTime(b) - cpuBefore

			b.ReportMetric(float64(cpu)/float64(time.Millisecond)/float64(b.N), "cpu-ms/op")
			b.ReportMetric(float64(returned), "files")
			if stage.exact && returned != wantFiles {
				b.Errorf("%s/%s returned %d files, git ls-files lists %d", stage.name, name, returned, wantFiles)
			}
		})
	}
}
