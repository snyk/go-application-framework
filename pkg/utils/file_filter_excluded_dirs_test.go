package utils

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/metrics"
)

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

func TestFileFilter_ExcludedDirectoriesAreNotFiltered(t *testing.T) {
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

			config := newTestConfig(map[string]bool{FF_FILE_FILTER_METACHARACTER_FIX: true})
			fileFilter := NewFileFilter(root, &log.Logger, WithConfig(config), WithRuleFiles([]string{test.ruleFile}))

			files := filterFiles(t, fileFilter)

			expected := []string{filepath.Join(root, test.ruleFile)}
			for _, file := range kept {
				expected = append(expected, filepath.Join(root, file))
			}
			assert.ElementsMatch(t, expected, files)

			rules, err := fileFilter.GetRules([]string{test.ruleFile})
			require.NoError(t, err)
			folders := fileFilter.newFolderExclusions(rules)
			nodeModules := filepath.Join(root, "node_modules") + string(filepath.Separator)
			excludedFiles := 0
			for file := range fileFilter.GetAllFiles() {
				if strings.HasPrefix(file, nodeModules) {
					excludedFiles++
					assert.True(t, folders.excludedByFolder(file), "%s must be excluded by its folder, not by matching every rule", file)
				}
			}
			assert.Equal(t, nodeModulesFiles, excludedFiles)
		})
	}
}

func TestFileFilter_ReIncludedFileInExcludedDirectoryIsKept(t *testing.T) {
	root, _ := createPnpmStyleMonorepo(t, 10)
	createFileInPath(t, filepath.Join(root, ".gitignore"), []byte("node_modules/*\n!node_modules/keep.js\n"))
	createFileInPath(t, filepath.Join(root, "node_modules", "keep.js"), []byte("x"))
	config := newTestConfig(map[string]bool{FF_FILE_FILTER_METACHARACTER_FIX: true})
	fileFilter := NewFileFilter(root, &log.Logger, WithConfig(config), WithRuleFiles([]string{".gitignore"}))

	files := filterFiles(t, fileFilter)

	assert.Contains(t, files, filepath.Join(root, "node_modules", "keep.js"))
}

func BenchmarkFileFilter_PnpmMonorepo(b *testing.B) {
	if testing.Short() {
		b.Skip("builds a fixture of about 40k files")
	}

	root, _ := createPnpmStyleMonorepo(b, 20000)
	createFileInPath(b, filepath.Join(root, ".gitignore"), []byte("node_modules/\n"))
	config := newTestConfig(map[string]bool{FF_FILE_FILTER_METACHARACTER_FIX: true})

	flows := []struct {
		name   string
		filter func(b *testing.B, fileFilter *FileFilter) <-chan string
	}{
		{name: "legacy", filter: func(b *testing.B, fileFilter *FileFilter) <-chan string {
			b.Helper()
			rules, err := fileFilter.GetRules([]string{".gitignore"})
			require.NoError(b, err)
			return fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), rules)
		}},
		{name: "WalkFilteredFiles", filter: func(b *testing.B, fileFilter *FileFilter) <-chan string {
			b.Helper()
			files, err := fileFilter.WalkFilteredFiles()
			require.NoError(b, err)
			return files
		}},
	}

	for _, flow := range flows {
		for _, threads := range []int{1, runtime.NumCPU()} {
			b.Run(fmt.Sprintf("%s/threads=%d", flow.name, threads), func(b *testing.B) {
				var inputFiles, outputFiles int
				b.ReportAllocs()
				for b.Loop() {
					metrics.ResetAccumulated()
					recorder := metrics.NewRecorderFake()
					fileFilter := NewFileFilter(root, &log.Logger, WithConfig(config), WithMetrics(recorder), WithThreadNumber(threads), WithRuleFiles([]string{".gitignore"}))

					outputFiles = 0
					for range flow.filter(b, fileFilter) {
						outputFiles++
					}
					inputFiles = recorder.IntValues[buildMetricKey(metriVariantMetacharFix, metricFilterInputFileCount)]
				}
				b.ReportMetric(float64(inputFiles), "input_files")
				b.ReportMetric(float64(outputFiles), "output_files")
			})
		}
	}
}

func TestFileFilter_ContentsGlobThenReIncludeIsKept(t *testing.T) {
	root := t.TempDir()
	createFileInPath(t, filepath.Join(root, ".gitignore"), []byte("X/**\n!X/keep\n"))
	createFileInPath(t, filepath.Join(root, "X", "keep"), []byte("x"))
	createFileInPath(t, filepath.Join(root, "X", "drop.txt"), []byte("x"))
	createFileInPath(t, filepath.Join(root, "src", "main.go"), []byte("x"))

	config := newTestConfig(map[string]bool{FF_FILE_FILTER_METACHARACTER_FIX: true})
	fileFilter := NewFileFilter(root, &log.Logger, WithConfig(config), WithRuleFiles([]string{".gitignore"}))

	files := filterFiles(t, fileFilter)

	expected := []string{
		filepath.Join(root, ".gitignore"),
		filepath.Join(root, "X", "keep"),
		filepath.Join(root, "src", "main.go"),
	}
	assert.ElementsMatch(t, expected, files)
}

func filterFiles(t *testing.T, fileFilter *FileFilter) []string {
	t.Helper()

	filesCh, err := fileFilter.WalkFilteredFiles()
	require.NoError(t, err)

	return drainFilteredFiles(t, filesCh)
}
