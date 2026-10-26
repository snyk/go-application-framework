package utils

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/metrics"
)

// createPnpmStyleMonorepo creates source files plus large excluded node_modules folders at the root and
// in a nested package. It returns the root and the relative paths of the files that must survive.
func createPnpmStyleMonorepo(tb testing.TB, nodeModulesFiles int) (string, []string) {
	tb.Helper()

	root := tb.TempDir()
	kept := []string{
		"package.json",
		filepath.Join("apps", "web", "src", "index.ts"),
		filepath.Join("apps", "web", "src", "app.ts"),
		filepath.Join("libs", "core", "src", "core.ts"),
	}
	for _, file := range kept {
		createFileInPath(tb, filepath.Join(root, file), []byte("x"))
	}

	for _, nodeModules := range []string{
		"node_modules",
		filepath.Join("apps", "web", "node_modules"),
	} {
		for i := 0; i < nodeModulesFiles; i++ {
			pkg := fmt.Sprintf("pkg-%d", i%50)
			createFileInPath(tb, filepath.Join(root, nodeModules, ".pnpm", pkg, fmt.Sprintf("file-%d.js", i)), []byte("x"))
		}
	}

	return root, kept
}

func TestFileFilter_ExcludedDirectoriesAreNotWalked(t *testing.T) {
	const nodeModulesFiles = 200

	for _, test := range []struct {
		name     string
		ruleFile string
		rules    string
	}{
		{name: ".gitignore", ruleFile: ".gitignore", rules: "node_modules/\n"},
		{name: ".snyk", ruleFile: ".snyk", rules: "exclude:\n  global:\n    - node_modules\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, kept := createPnpmStyleMonorepo(t, nodeModulesFiles)
			createFileInPath(t, filepath.Join(root, test.ruleFile), []byte(test.rules))

			recorder := newMetricsRecorder(t)
			config := newTestConfig(map[string]bool{FF_FILE_FILTER_METACHARACTER_FIX: true})
			fileFilter := NewFileFilter(root, &log.Logger, WithConfig(config), WithMetrics(recorder))

			files := runFileFilter(t, fileFilter, test.ruleFile)

			expected := []string{filepath.Join(root, test.ruleFile)}
			for _, file := range kept {
				expected = append(expected, filepath.Join(root, file))
			}
			assert.ElementsMatch(t, expected, files)

			variant := recordedMetrics(t, recorder)[metriVariantMetacharFix]
			assert.Equal(t, len(expected), variant.ints[metricFilterInputFileCount],
				"files inside excluded folders must not reach the filter")
		})
	}
}

func TestFileFilter_ReIncludedFileInExcludedDirectoryIsKept(t *testing.T) {
	root, _ := createPnpmStyleMonorepo(t, 10)
	createFileInPath(t, filepath.Join(root, ".gitignore"), []byte("node_modules/*\n!node_modules/keep.js\n"))
	createFileInPath(t, filepath.Join(root, "node_modules", "keep.js"), []byte("x"))
	config := newTestConfig(map[string]bool{FF_FILE_FILTER_METACHARACTER_FIX: true})
	fileFilter := NewFileFilter(root, &log.Logger, WithConfig(config))

	files := runFileFilter(t, fileFilter, ".gitignore")

	assert.Contains(t, files, filepath.Join(root, "node_modules", "keep.js"))
}

// BenchmarkFileFilter_PnpmMonorepo runs the complete file-filter flow on a synthetic tree with large excluded
// folders. input_files shows how many paths reached the filter and output_files how many survived.
//
// Run with:
//
//	go test ./pkg/utils -run '^$' -bench '^BenchmarkFileFilter_PnpmMonorepo$' -benchmem -count=5
func BenchmarkFileFilter_PnpmMonorepo(b *testing.B) {
	root, _ := createPnpmStyleMonorepo(b, 20000)
	createFileInPath(b, filepath.Join(root, ".gitignore"), []byte("node_modules/\n"))
	config := newTestConfig(map[string]bool{FF_FILE_FILTER_METACHARACTER_FIX: true})

	for _, threads := range []int{1, runtime.NumCPU()} {
		b.Run(fmt.Sprintf("threads=%d", threads), func(b *testing.B) {
			var inputFiles, outputFiles int
			b.ReportAllocs()
			for b.Loop() {
				metrics.ResetAccumulated()
				recorder := metrics.NewRecorderFake()
				fileFilter := NewFileFilter(root, &log.Logger, WithConfig(config), WithMetrics(recorder), WithThreadNumber(threads))
				rules, err := fileFilter.GetRules([]string{".gitignore"})
				require.NoError(b, err)

				outputFiles = 0
				for range fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), rules) {
					outputFiles++
				}
				inputFiles = recorder.IntValues[buildMetricKey(metriVariantMetacharFix, metricFilterInputFileCount)]
			}
			b.ReportMetric(float64(inputFiles), "input_files")
			b.ReportMetric(float64(outputFiles), "output_files")
		})
	}
}
