package utils

import (
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

func drainChannelToSortedSlice(ch chan string) []string {
	var out []string
	for v := range ch {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// TestFileFilter_GetFilteredFilesSingleWalk_EquivalentToPipeline asserts the new
// single-walk implementation returns exactly the same set of files as the
// original GetAllFiles + GetRules + GetFilteredFiles pipeline across every
// existing test case (including nested ignore files and negation-in-ignored-dir).
func TestFileFilter_GetFilteredFilesSingleWalk_EquivalentToPipeline(t *testing.T) {
	for _, testCase := range testCases(t) {
		t.Run(testCase.name, func(t *testing.T) {
			setupTestFileSystem(t, testCase)

			oldFilter := NewFileFilter(testCase.repoPath, &log.Logger)
			globs, err := oldFilter.GetRules(testCase.ruleFiles)
			assert.NoError(t, err)
			oldResult := drainChannelToSortedSlice(
				oldFilter.GetFilteredFiles(oldFilter.GetAllFiles(), globs),
			)

			newFilter := NewFileFilter(testCase.repoPath, &log.Logger)
			newResult := drainChannelToSortedSlice(
				newFilter.GetFilteredFilesSingleWalk(testCase.ruleFiles),
			)

			// The shared test fixture only writes ignore files to disk (regular
			// files like file1.java are never created), so the canonical
			// correctness check is exact equivalence with the original pipeline
			// over whatever actually exists on disk.
			assert.Equal(t, oldResult, newResult,
				"single-walk result differs from the original pipeline")
		})
	}
}

// setupNodeModulesTree builds a small "source" tree plus a large ignored
// directory (simulating node_modules) that the root .gitignore excludes. Returns
// the root and the number of non-ignored files.
func setupNodeModulesTree(tb testing.TB, ignoredFiles int) (root string, wantFiles int) {
	tb.Helper()
	root = tb.TempDir()

	// root .gitignore excluding node_modules
	createFileInPath(tb, filepath.Join(root, ".gitignore"), []byte("node_modules\n"))

	// a handful of real source files
	src := []string{"src/index.js", "src/app.js", "lib/util.js"}
	for _, f := range src {
		createFileInPath(tb, filepath.Join(root, f), []byte("console.log(1)"))
	}

	// a large node_modules that should be pruned entirely
	for i := 0; i < ignoredFiles; i++ {
		p := filepath.Join(root, "node_modules", fmt.Sprintf("pkg_%d", i%50), fmt.Sprintf("file_%d.js", i))
		createFileInPath(tb, p, []byte("module.exports={}"))
	}

	// expected: the source files + the .gitignore itself
	return root, len(src) + 1
}

func TestFileFilter_GetFilteredFilesSingleWalk_PrunesNodeModules(t *testing.T) {
	root, want := setupNodeModulesTree(t, 500)
	ff := NewFileFilter(root, &log.Logger)
	got := drainChannelToSortedSlice(ff.GetFilteredFilesSingleWalk([]string{".gitignore", ".dcignore", ".snyk"}))
	assert.Len(t, got, want)
	for _, f := range got {
		assert.NotContains(t, f, "node_modules", "node_modules files must be filtered out")
	}
}

// buildRealTree writes every file in files (relative path -> content) under a
// fresh temp dir and returns the root. Unlike the shared setupTestFileSystem
// fixture, this creates *all* files on disk so behavior can be asserted exactly.
func buildRealTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		createFileInPath(t, filepath.Join(root, rel), []byte(content))
	}
	return root
}

// TestFileFilter_GetFilteredFilesSingleWalk_NegationScenarios pins down the exact
// behavior for the directory-pruning edge cases discovered against real repos:
// negations that re-include content inside an otherwise-ignored directory must
// still be honored (the directory must not be pruned), while wholly-excluded
// directories must be pruned. Each case is asserted both against an explicit
// expected set and for exact equivalence with the original pipeline.
func TestFileFilter_GetFilteredFilesSingleWalk_NegationScenarios(t *testing.T) {
	ruleFiles := []string{".gitignore", ".dcignore", ".snyk"}

	cases := []struct {
		name     string
		files    map[string]string
		expected []string // relative paths expected in the output
	}{
		{
			// `src/*` ignores src's children; `!src/keep` re-includes a subdir.
			// The bug: pruning `src` dropped everything under src/keep.
			name: "negation re-includes subdir of contents-ignored dir",
			files: map[string]string{
				".gitignore":      "src/*\n!src/keep\n",
				"main.js":         "x",
				"src/c.js":        "x",
				"src/drop/b.js":   "x",
				"src/keep/a.js":   "x",
				"src/keep/n/d.js": "x",
			},
			expected: []string{".gitignore", "main.js", "src/keep/a.js", "src/keep/n/d.js"},
		},
		{
			// `obj/**` (+ trailing-slash variant) ignores obj's contents;
			// `!*.assets.json` re-includes one file. The bug: `obj/**/` was
			// mis-read as a whole-dir exclusion and pruned obj.
			name: "negation re-includes file under content-ignored dir",
			files: map[string]string{
				".gitignore":              "obj/**\nobj/**/\n!*.assets.json\n",
				"app.cs":                  "x",
				"obj/project.assets.json": "x",
				"obj/foo.dll":             "x",
				"obj/sub/bar.dll":         "x",
			},
			expected: []string{".gitignore", "app.cs", "obj/project.assets.json"},
		},
		{
			// Leading+trailing slash form: a true whole-directory exclusion that
			// MUST be pruned.
			name: "whole-directory exclusion is pruned",
			files: map[string]string{
				".gitignore":            "/node_modules/\n",
				"src/app.js":            "x",
				"node_modules/pkg/i.js": "x",
				"node_modules/pkg/j.js": "x",
			},
			expected: []string{".gitignore", "src/app.js"},
		},
		{
			// `**/dist` excludes dist directories at any depth -> pruned.
			name: "globstar directory exclusion pruned at any depth",
			files: map[string]string{
				".gitignore":  "**/dist\n",
				"a/keep.js":   "x",
				"dist/y.js":   "x",
				"a/dist/x.js": "x",
			},
			expected: []string{".gitignore", "a/keep.js"},
		},
		{
			// `/a/` excludes dir a, but a/.gitignore re-includes *.txt. Behavior
			// is preserved (not git-strict): the dir owning an ignore file is not
			// pruned, so the negation is honored.
			name: "ignored dir with its own negating ignore file is not pruned",
			files: map[string]string{
				".gitignore":   "/a/\n",
				"a/.gitignore": "!*.txt\n",
				"a/keep.txt":   "x",
				"a/drop.js":    "x",
				"b.js":         "x",
			},
			expected: []string{".gitignore", "a/keep.txt", "b.js"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := buildRealTree(t, tc.files)

			want := make([]string, 0, len(tc.expected))
			for _, rel := range tc.expected {
				want = append(want, filepath.Join(root, rel))
			}
			sort.Strings(want)

			got := drainChannelToSortedSlice(
				NewFileFilter(root, &log.Logger).GetFilteredFilesSingleWalk(ruleFiles),
			)
			assert.Equal(t, want, got, "single-walk output does not match expected set")

			// Cross-check: identical to the original pipeline on real files.
			old := NewFileFilter(root, &log.Logger)
			globs, err := old.GetRules(ruleFiles)
			assert.NoError(t, err)
			oldResult := drainChannelToSortedSlice(old.GetFilteredFiles(old.GetAllFiles(), globs))
			assert.Equal(t, oldResult, got, "single-walk diverges from original pipeline")
		})
	}
}

func BenchmarkFileFilter_Pipeline_vs_SingleWalk(b *testing.B) {
	root, _ := setupNodeModulesTree(b, 20000)
	ruleFiles := []string{".gitignore", ".dcignore", ".snyk"}

	b.Run("OldPipeline", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			ff := NewFileFilter(root, &log.Logger, WithThreadNumber(runtime.NumCPU()))
			globs, err := ff.GetRules(ruleFiles)
			assert.NoError(b, err)
			for range ff.GetFilteredFiles(ff.GetAllFiles(), globs) {
			}
		}
	})

	b.Run("SingleWalkPruning", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			ff := NewFileFilter(root, &log.Logger, WithThreadNumber(runtime.NumCPU()))
			for range ff.GetFilteredFilesSingleWalk(ruleFiles) {
			}
		}
	})
}
