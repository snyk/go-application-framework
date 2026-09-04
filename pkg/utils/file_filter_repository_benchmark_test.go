package utils

import (
	"os"
	"testing"

	"github.com/rs/zerolog/log"
)

const fileFilterBenchmarkRepoEnv = "GAF_FILE_FILTER_BENCHMARK_REPO"

// BenchmarkFileFilter_Repository compares the complete file-filter flow with tracked-file-aware
// .gitignore handling disabled and enabled against the same existing repository.
//
// Run with:
//
//	GAF_FILE_FILTER_BENCHMARK_REPO=/path/to/repo \
//	  go test ./pkg/utils -run '^$' -bench '^BenchmarkFileFilter_Repository$' -benchmem -count=5
func BenchmarkFileFilter_Repository(b *testing.B) {
	repoPath := os.Getenv(fileFilterBenchmarkRepoEnv)
	if repoPath == "" {
		b.Skipf("set %s to an existing Git repository", fileFilterBenchmarkRepoEnv)
	}

	benchmarks := []struct {
		name                string
		respectTrackedFiles bool
	}{
		{
			name:                "feature_flag=off",
			respectTrackedFiles: false,
		},
		{
			name:                "feature_flag=on",
			respectTrackedFiles: true,
		},
	}

	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			config := newTestConfig(map[string]bool{
				FF_FILE_FILTER_METACHARACTER_FIX:   true,
				FF_GITIGNORE_RESPECT_TRACKED_FILES: benchmark.respectTrackedFiles,
			})

			var outputFileCount int
			b.ReportAllocs()
			for b.Loop() {
				fileFilter := NewFileFilter(repoPath, &log.Logger, WithConfig(config))
				rules, err := fileFilter.GetRules([]string{".gitignore"})
				if err != nil {
					b.Fatal(err)
				}

				outputFileCount = 0
				for range fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), rules) {
					outputFileCount++
				}
			}

			b.ReportMetric(float64(outputFileCount), "output_files")
		})
	}
}
