package utils

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

const fileFilterBenchmarkRepoEnv = "GAF_FILE_FILTER_BENCHMARK_REPO"

// BenchmarkFileFilter_Repository compares both matchers and tracked-file handling,
// including rule discovery and draining the complete filtered file stream.
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

	filterFiles := func(b *testing.B, ripgrep, tracked bool) []string {
		b.Helper()
		var logs strings.Builder
		logger := zerolog.New(&logs).Level(zerolog.WarnLevel)
		config := newTestConfig(map[string]bool{
			FF_FILE_FILTER_METACHARACTER_FIX:   true,
			FF_GITIGNORE_RESPECT_TRACKED_FILES: tracked,
			fileFilterRipgrepEnabled:           ripgrep,
		})
		filter := NewFileFilter(repoPath, &logger, WithConfig(config))
		rules, err := filter.GetRules([]string{".gitignore"})
		if err != nil {
			b.Fatal(err)
		}
		var paths []string
		for file := range filter.GetFilteredFiles(filter.GetAllFiles(), rules) {
			paths = append(paths, file)
		}
		if ripgrep && strings.Contains(logs.String(), "falling back") {
			b.Fatalf("ripgrep benchmark used fallback: %s", logs.String())
		}
		return paths
	}
	for _, tracked := range []bool{false, true} {
		baseline := filterFiles(b, false, tracked)
		slices.Sort(baseline)
		candidate := filterFiles(b, true, tracked)
		slices.Sort(candidate)
		if !slices.Equal(baseline, candidate) {
			first := 0
			for first < min(len(baseline), len(candidate)) && baseline[first] == candidate[first] {
				first++
			}
			b.Fatalf("matcher output differs (tracked=%t): existing=%d ripgrep=%d; first difference existing=%q ripgrep=%q", tracked, len(baseline), len(candidate), baseline[first:min(first+1, len(baseline))], candidate[first:min(first+1, len(candidate))])
		}
		for _, ripgrep := range []bool{false, true} {
			b.Run(fmt.Sprintf("ripgrep=%t/tracked=%t", ripgrep, tracked), func(b *testing.B) {
				var outputFileCount int
				b.ReportAllocs()
				for b.Loop() {
					outputFileCount = len(filterFiles(b, ripgrep, tracked))
					if outputFileCount != len(baseline) {
						b.Fatalf("file count changed during benchmark: got %d want %d", outputFileCount, len(baseline))
					}
				}

				b.ReportMetric(float64(outputFileCount), "output_files")
			})
		}
	}
}
