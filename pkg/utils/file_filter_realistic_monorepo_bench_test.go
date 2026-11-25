package utils

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

// createRealisticMonorepo builds a monorepo of about 48k files: a root node_modules of 30k files and
// 200 packages, each with its own .gitignore, sources, build output, logs and a nested node_modules.
func createRealisticMonorepo(tb testing.TB) string {
	tb.Helper()

	const (
		rootNodeModulesFiles    = 30000
		rootNodeModulesPackages = 300
		packages                = 200
		sourceFiles             = 25
		sourceDirs              = 5
		distFiles               = 5
		buildFiles              = 3
		logFiles                = 2
		fixtureFiles            = 2
		nestedNodeModulesFiles  = 50
	)

	root := tb.TempDir()
	createFileInPath(tb, filepath.Join(root, ".gitignore"), []byte(realisticMonorepoGitignore))
	createFileInPath(tb, filepath.Join(root, ".dcignore"), []byte("**/__fixtures__/**\n*.min.js\n"))
	createFileInPath(tb, filepath.Join(root, ".snyk"), []byte("exclude:\n  global:\n    - vendor/**\n"))

	for i := 0; i < rootNodeModulesFiles; i++ {
		pkg := fmt.Sprintf("pkg-%d", i%rootNodeModulesPackages)
		name := fmt.Sprintf("file-%d.js", i)
		if i%100 == 0 {
			name = fmt.Sprintf("file-%d.config.js", i)
		}
		createFileInPath(tb, filepath.Join(root, "node_modules", pkg, "lib", name), []byte("x"))
	}

	for p := 0; p < packages; p++ {
		pkgRoot := filepath.Join(root, "packages", fmt.Sprintf("pkg-%d", p))
		createFileInPath(tb, filepath.Join(pkgRoot, ".gitignore"), []byte("build/\n*.tmp\n/generated/\n.env.local\n"))

		for i := 0; i < sourceFiles; i++ {
			createFileInPath(tb, filepath.Join(pkgRoot, "src", fmt.Sprintf("sub%d", i%sourceDirs), fmt.Sprintf("file-%d.ts", i)), []byte("x"))
		}
		for i := 0; i < distFiles; i++ {
			createFileInPath(tb, filepath.Join(pkgRoot, "dist", fmt.Sprintf("bundle-%d.js", i)), []byte("x"))
		}
		for i := 0; i < buildFiles; i++ {
			createFileInPath(tb, filepath.Join(pkgRoot, "build", fmt.Sprintf("artifact-%d.o", i)), []byte("x"))
		}
		for i := 0; i < logFiles; i++ {
			createFileInPath(tb, filepath.Join(pkgRoot, fmt.Sprintf("app-%d.log", i)), []byte("x"))
		}
		for i := 0; i < fixtureFiles; i++ {
			createFileInPath(tb, filepath.Join(pkgRoot, "src", "__fixtures__", fmt.Sprintf("fixture-%d.json", i)), []byte("x"))
		}
		for i := 0; i < nestedNodeModulesFiles; i++ {
			createFileInPath(tb, filepath.Join(pkgRoot, "node_modules", fmt.Sprintf("dep-%d", i%10), fmt.Sprintf("index-%d.js", i)), []byte("x"))
		}
	}

	return root
}

const realisticMonorepoGitignore = "node_modules/\ndist/\ncoverage/\n*.log\n.cache/\n"

// BenchmarkFileFilter_RealisticMonorepo compares the legacy flow (GetRules, then GetFilteredFiles over
// GetAllFiles) with WalkFilteredFiles on the fixture from createRealisticMonorepo, once with the
// fixture's rules and once with a top-level negation added to the root .gitignore.
//
//	go test ./pkg/utils -run '^$' -bench '^BenchmarkFileFilter_RealisticMonorepo$' -benchmem -benchtime=5x
//
// Profile one flow at a time, so the profile is not a mix of both:
//
//	go test ./pkg/utils -run '^$' -bench '^BenchmarkFileFilter_RealisticMonorepo/no-negation/WalkFilteredFiles$' \
//	  -benchtime=5x -cpuprofile cpu.out -memprofile mem.out
//	go tool pprof -top -cum -focus '\(\*FileFilter\)|exclusionPredicate|ruleMatcher' cpu.out
//	go tool pprof -top -cum -sample_index=alloc_space -focus '\(\*FileFilter\)|exclusionPredicate|ruleMatcher' mem.out
//	go tool pprof -http=:8080 cpu.out
//
// The fixture is built in the same process, so -focus is needed to keep its file writes out of the
// profiles. Add -memprofilerate=1 for exact allocation sites, at the cost of a much slower run.
func BenchmarkFileFilter_RealisticMonorepo(b *testing.B) {
	if testing.Short() {
		b.Skip("builds a fixture of about 48k files")
	}

	root := createRealisticMonorepo(b)
	ruleFiles := []string{".gitignore", ".dcignore", ".snyk"}
	config := newTestConfig(map[string]bool{FF_FILE_FILTER_METACHARACTER_FIX: true})
	logger := zerolog.Nop()

	legacy := func() int {
		fileFilter := NewFileFilter(root, &logger, WithConfig(config))
		rules, err := fileFilter.GetRules(ruleFiles)
		require.NoError(b, err)

		files := 0
		for range fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), rules) {
			files++
		}
		return files
	}

	for _, rules := range []struct {
		name      string
		gitignore string
	}{
		{name: "no-negation", gitignore: realisticMonorepoGitignore},
		{name: "top-level-negation", gitignore: realisticMonorepoGitignore + "!*.config.js\n"},
	} {
		createFileInPath(b, filepath.Join(root, ".gitignore"), []byte(rules.gitignore))
		legacyFiles := legacy()

		b.Run(rules.name+"/legacy", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				legacy()
			}
			b.ReportMetric(float64(legacyFiles), "files/op")
		})

		b.Run(rules.name+"/WalkFilteredFiles", func(b *testing.B) {
			var files int
			b.ReportAllocs()
			for b.Loop() {
				fileFilter := NewFileFilter(root, &logger, WithConfig(config), WithRuleFiles(ruleFiles))
				filesCh, err := fileFilter.WalkFilteredFiles()
				require.NoError(b, err)

				files = 0
				for range filesCh {
					files++
				}
			}
			b.ReportMetric(float64(files), "files/op")
			require.Equal(b, legacyFiles, files)
		})
	}
}
