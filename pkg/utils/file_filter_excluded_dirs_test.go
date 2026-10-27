package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/go-git/go-git/v5"
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

			files := filterFiles(t, fileFilter, test.ruleFile)

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

	files := filterFiles(t, fileFilter, ".gitignore")

	assert.Contains(t, files, filepath.Join(root, "node_modules", "keep.js"))
}

func BenchmarkFileFilter_PnpmMonorepo(b *testing.B) {
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
			files, err := fileFilter.WalkFilteredFiles([]string{".gitignore"})
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
					fileFilter := NewFileFilter(root, &log.Logger, WithConfig(config), WithMetrics(recorder), WithThreadNumber(threads))

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

func TestFileFilter_UnreadableDirectoryDoesNotStopRuleCollection(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory permissions are not enforced")
	}

	root := t.TempDir()
	locked := filepath.Join(root, "a-locked")
	require.NoError(t, os.Mkdir(locked, 0o755))
	require.NoError(t, os.Chmod(locked, 0o000))
	t.Cleanup(func() { assert.NoError(t, os.Chmod(locked, 0o755)) })
	createFileInPath(t, filepath.Join(root, "z", ".gitignore"), []byte("token.txt\n"))
	config := newTestConfig(map[string]bool{FF_FILE_FILTER_METACHARACTER_FIX: true})
	fileFilter := NewFileFilter(root, &log.Logger, WithConfig(config))

	createFileInPath(t, filepath.Join(root, "z", "token.txt"), []byte("x"))
	createFileInPath(t, filepath.Join(root, "z", "code.ts"), []byte("x"))

	files := filterFiles(t, fileFilter, ".gitignore")

	assert.Contains(t, files, filepath.Join(root, "z", "code.ts"))
	assert.NotContains(t, files, filepath.Join(root, "z", "token.txt"))
}

func TestFileFilter_trackedFilesAreLoadedOnceUntilReleased(t *testing.T) {
	root := t.TempDir()
	createFileInPath(t, filepath.Join(root, "tracked.ts"), []byte("x"))
	repo, err := git.PlainInit(root, false)
	require.NoError(t, err)
	worktree, err := repo.Worktree()
	require.NoError(t, err)
	_, err = worktree.Add("tracked.ts")
	require.NoError(t, err)
	fileFilter := NewFileFilter(root, &log.Logger)

	first, ok := fileFilter.loadTrackedFiles()
	require.True(t, ok)
	second, _ := fileFilter.loadTrackedFiles()
	fileFilter.releaseTrackedFiles()
	third, _ := fileFilter.loadTrackedFiles()

	assert.Same(t, first, second)
	assert.NotSame(t, first, third)
	assert.True(t, first.paths["tracked.ts"])
}

func filterFiles(t *testing.T, fileFilter *FileFilter, ruleFile string, options ...WalkFilteredFilesOption) []string {
	t.Helper()

	filesCh, err := fileFilter.WalkFilteredFiles([]string{ruleFile}, options...)
	require.NoError(t, err)

	return drainFilteredFiles(t, filesCh)
}
