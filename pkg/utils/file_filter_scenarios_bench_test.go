package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type benchmarkWorkload struct {
	name string
	root string
	// wantFiles is how many files a correct filter returns, so a wrong result shows up.
	wantFiles int
}

// BenchmarkScenarioWorkloads runs every registered implementation over the same three large
// trees. The trees have no .git folder.
func BenchmarkScenarioWorkloads(b *testing.B) {
	workloads := []benchmarkWorkload{
		buildIgnoredNodeModulesWorkload(b),
		buildNestedRulesWorkload(b),
		buildFlatWorkload(b),
	}

	for _, impl := range scenarioImplementations {
		for _, workload := range workloads {
			b.Run(impl.name+"/"+workload.name, func(b *testing.B) {
				var returned int
				for b.Loop() {
					returned = len(impl.run(b, workload.root, scenarioOptions{}))
				}

				b.ReportMetric(float64(returned), "files")
				b.Logf("%s/%s returned %d files, want %d", impl.name, workload.name, returned, workload.wantFiles)
				if returned != workload.wantFiles {
					b.Errorf("%s/%s returned %d files, want %d", impl.name, workload.name, returned, workload.wantFiles)
				}
			})
		}
	}
}

// buildIgnoredNodeModulesWorkload: 40,000 files under an ignored node_modules and 2,000 elsewhere.
func buildIgnoredNodeModulesWorkload(b *testing.B) benchmarkWorkload {
	b.Helper()

	root := newScenarioTempDir(b, "workload-node-modules")
	writeScenarioFile(b, filepath.Join(root, ".gitignore"), ruleLines(
		"node_modules/", "dist/", "build/", "coverage/", "tmp/", "out/", "target/", "vendor/", ".cache/", "__pycache__/",
		".idea/", ".vscode/", "*.log", "*.tmp", "*.bak", "*.swp", "*.pyc", "*.orig", ".env", ".DS_Store",
	))
	writeManyFiles(b, filepath.Join(root, "node_modules"), 400, 100, "index.js")
	writeManyFiles(b, filepath.Join(root, "src"), 100, 20, "file.js")

	return benchmarkWorkload{name: "ignored-node-modules-40k", root: root, wantFiles: 2000 + 1}
}

// buildNestedRulesWorkload: 2,000 folders, each with its own .gitignore of 20 rules and 20 files,
// 4 of which match a rule.
func buildNestedRulesWorkload(b *testing.B) benchmarkWorkload {
	b.Helper()

	root := newScenarioTempDir(b, "workload-nested-rules")
	rules := ruleLines(
		"*.log", "*.tmp", "*.bak", "*.swp", "*.pyc", "*.orig", "build/", "dist/", "coverage/", "tmp/",
		"out/", "target/", ".cache/", "__pycache__/", ".idea/", ".vscode/", ".env", ".DS_Store", "/local-only.txt", "*.rej",
	)
	for group := range 40 {
		for folder := range 50 {
			dir := filepath.Join(root, fmt.Sprintf("group%02d", group), fmt.Sprintf("dir%02d", folder))
			require.NoError(b, os.MkdirAll(dir, 0o755))
			writeScenarioFile(b, filepath.Join(dir, ".gitignore"), rules)
			for file := range 16 {
				writeScenarioFile(b, filepath.Join(dir, fmt.Sprintf("f%02d.txt", file)), "")
			}
			for _, name := range []string{"x.log", "x.tmp", "x.bak", "x.swp"} {
				writeScenarioFile(b, filepath.Join(dir, name), "")
			}
		}
	}

	return benchmarkWorkload{name: "nested-rules-2000-dirs", root: root, wantFiles: 2000 * (16 + 1)}
}

// buildFlatWorkload: 100,000 files in 1,000 folders and one root .gitignore of 50 rules; 10 files
// per folder match a rule.
func buildFlatWorkload(b *testing.B) benchmarkWorkload {
	b.Helper()

	root := newScenarioTempDir(b, "workload-flat")
	rules := []string{"*.log", "node_modules/", "dist/", "build/", "coverage/", "tmp/", "*.tmp", "*.bak", ".env", ".DS_Store"}
	for i := len(rules); i < 50; i++ {
		rules = append(rules, fmt.Sprintf("*.unused%02d", i))
	}
	writeScenarioFile(b, filepath.Join(root, ".gitignore"), ruleLines(rules...))
	for folder := range 1000 {
		dir := filepath.Join(root, fmt.Sprintf("dir%04d", folder))
		require.NoError(b, os.MkdirAll(dir, 0o755))
		for file := range 90 {
			writeScenarioFile(b, filepath.Join(dir, fmt.Sprintf("src%02d.txt", file)), "")
		}
		for file := range 10 {
			writeScenarioFile(b, filepath.Join(dir, fmt.Sprintf("gen%d.log", file)), "")
		}
	}

	return benchmarkWorkload{name: "flat-100k", root: root, wantFiles: 1000*90 + 1}
}

// writeManyFiles creates folderCount folders under base, each holding filesPerFolder files.
func writeManyFiles(b *testing.B, base string, folderCount, filesPerFolder int, fileSuffix string) {
	b.Helper()

	for folder := range folderCount {
		dir := filepath.Join(base, fmt.Sprintf("pkg%03d", folder))
		require.NoError(b, os.MkdirAll(dir, 0o755))
		for file := range filesPerFolder {
			writeScenarioFile(b, filepath.Join(dir, fmt.Sprintf("%03d-%s", file, fileSuffix)), "")
		}
	}
}
