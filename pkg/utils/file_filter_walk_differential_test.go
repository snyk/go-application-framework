package utils

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var differentialRuleFiles = []string{".gitignore", ".dcignore", ".snyk"}

var differentialFlagCombinations = []struct {
	name  string
	flags map[string]bool
}{
	{name: "tracked=false,metachar=false", flags: map[string]bool{FF_GITIGNORE_RESPECT_TRACKED_FILES: false, FF_FILE_FILTER_METACHARACTER_FIX: false}},
	{name: "tracked=false,metachar=true", flags: map[string]bool{FF_GITIGNORE_RESPECT_TRACKED_FILES: false, FF_FILE_FILTER_METACHARACTER_FIX: true}},
	{name: "tracked=true,metachar=false", flags: map[string]bool{FF_GITIGNORE_RESPECT_TRACKED_FILES: true, FF_FILE_FILTER_METACHARACTER_FIX: false}},
	{name: "tracked=true,metachar=true", flags: map[string]bool{FF_GITIGNORE_RESPECT_TRACKED_FILES: true, FF_FILE_FILTER_METACHARACTER_FIX: true}},
}

// assertSameAsLegacy compares WalkFilteredFiles with GetFilteredFiles(GetAllFiles(), extraRules + GetRules()).
func assertSameAsLegacy(t *testing.T, root string, flags map[string]bool, extraRules ...string) {
	t.Helper()

	config := newTestConfig(flags)
	legacy := NewFileFilter(root, &log.Logger, WithConfig(config))
	rules, legacyErr := legacy.GetRules(differentialRuleFiles)

	walk := NewFileFilter(root, &log.Logger, WithConfig(config), WithRuleFiles(differentialRuleFiles), WithExtraRules(extraRules))
	walkFiles, walkErr := walk.WalkFilteredFiles()

	if legacyErr != nil {
		assert.Error(t, walkErr)
		return
	}
	require.NoError(t, walkErr)

	legacyFiles := drainFilteredFiles(t, legacy.GetFilteredFiles(legacy.GetAllFiles(), slices.Concat(extraRules, rules)))
	assert.ElementsMatch(t, legacyFiles, drainFilteredFiles(t, walkFiles))
}

func skipWithoutPermissions(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("file permissions are not enforced")
	}
}

func lockPath(t *testing.T, path string, restoreMode os.FileMode) {
	t.Helper()
	require.NoError(t, os.Chmod(path, 0o000))
	t.Cleanup(func() { assert.NoError(t, os.Chmod(path, restoreMode)) })
}

func TestWalkFilteredFiles_MatchesLegacy(t *testing.T) {
	cases := []struct {
		name       string
		files      map[string]string
		tracked    []string
		extraRules []string
		setup      func(t *testing.T, root string)
	}{
		{
			name: "negation in parent folder",
			files: map[string]string{
				".gitignore":               "node_modules/\n!node_modules/pkg/keep.js\n",
				"node_modules/pkg/keep.js": "x",
				"node_modules/pkg/drop.js": "x",
				"src/a.js":                 "x",
			},
		},
		{
			name: "top-level negation",
			files: map[string]string{
				".gitignore":                         "node_modules/\n*.log\n!*.config.js\n!important.log\n",
				"node_modules/pkg/webpack.config.js": "x",
				"node_modules/pkg/index.js":          "x",
				"important.log":                      "x",
				"other.log":                          "x",
				"src/a.js":                           "x",
			},
		},
		{
			name: "nested .gitignore negation inside ignored folder",
			files: map[string]string{
				".gitignore":                  "node_modules/\n",
				"node_modules/pkg/.gitignore": "!keep.js\n",
				"node_modules/pkg/keep.js":    "x",
				"node_modules/pkg/drop.js":    "x",
				"src/a.js":                    "x",
			},
		},
		{
			name: "nested .dcignore negation inside ignored folder",
			files: map[string]string{
				".gitignore":           "vendor/\n",
				"vendor/lib/.dcignore": "*.tmp\n!keep.js\n",
				"vendor/lib/keep.js":   "x",
				"vendor/lib/a.tmp":     "x",
				"vendor/lib/other.js":  "x",
			},
		},
		{
			name: "nested .snyk inside ignored folder",
			files: map[string]string{
				".gitignore":  "build/\n",
				"build/.snyk": "exclude:\n  global:\n    - \"*.gen\"\n",
				"build/a.gen": "x",
				"build/b.js":  "x",
				"main.go":     "x",
			},
		},
		{
			name: "deep ignored folder with nested negation two levels down",
			files: map[string]string{
				".gitignore":          "dist/\n",
				"dist/a/b/.gitignore": "!keep.map\n",
				"dist/a/b/keep.map":   "x",
				"dist/a/b/c.js":       "x",
				"dist/x.js":           "x",
			},
		},
		{
			name: "contents glob then re-include",
			files: map[string]string{
				".gitignore":  "X/**\n!X/keep\n",
				"X/keep":      "x",
				"X/drop.txt":  "x",
				"src/main.go": "x",
			},
		},
		{
			name: "negation re-including the folder itself",
			files: map[string]string{
				".gitignore":        "node_modules/\n!node_modules/\n",
				"node_modules/a.js": "x",
				"src/a.js":          "x",
			},
		},
		{
			name: "negation from a folder whose name has regex metacharacters",
			files: map[string]string{
				".gitignore":      "ab/\n",
				"a(b)/.gitignore": "!x.js\n",
				"ab/x.js":         "x",
				"ab/y.js":         "x",
				"a(b)/z.js":       "x",
			},
		},
		{
			name: "extra rules from the caller",
			files: map[string]string{
				".gitignore":               "!node_modules/keep.js\n",
				"node_modules/keep.js":     "x",
				"node_modules/pkg/drop.js": "x",
				"src/a.js":                 "x",
			},
			extraRules: []string{"**/node_modules/**"},
		},
		{
			name: "tracked files in ignored folder",
			files: map[string]string{
				".gitignore":          "vendor/\n",
				"vendor/.dcignore":    "*.log\n",
				"vendor/lib.go":       "x",
				"vendor/other.log":    "x",
				"vendor/untracked.go": "x",
			},
			tracked: []string{"vendor/lib.go", "vendor/other.log", ".gitignore"},
		},
		{
			name: "newline in a file name inside an ignored folder",
			files: map[string]string{
				".gitignore":        "node_modules/\n",
				"node_modules/c.js": "x",
			},
			setup: func(t *testing.T, root string) {
				t.Helper()
				if runtime.GOOS == "windows" {
					t.Skip("file names cannot contain a newline")
				}
				createFileInPath(t, filepath.Join(root, "node_modules", "a\nb.js"), []byte("x"))
			},
		},
		{
			name: "unreadable folder inside an ignored folder",
			files: map[string]string{
				".gitignore":         "node_modules/\n",
				"node_modules/ok.js": "x",
				"src/a.js":           "x",
			},
			setup: func(t *testing.T, root string) {
				t.Helper()
				skipWithoutPermissions(t)
				locked := filepath.Join(root, "node_modules", "locked")
				require.NoError(t, os.Mkdir(locked, 0o755))
				lockPath(t, locked, 0o755)
			},
		},
		{
			name: "unreadable top-level folder before nested rules",
			files: map[string]string{
				"z/.gitignore": "token.txt\n",
				"z/token.txt":  "x",
				"z/code.ts":    "x",
			},
			setup: func(t *testing.T, root string) {
				t.Helper()
				skipWithoutPermissions(t)
				locked := filepath.Join(root, "a-locked")
				require.NoError(t, os.Mkdir(locked, 0o755))
				lockPath(t, locked, 0o755)
			},
		},
		{
			name: "unreadable rule file",
			files: map[string]string{
				".gitignore":   "ignored/\n",
				"ignored/a.ts": "x",
				"z/.gitignore": "token.txt\n",
				"z/code.ts":    "x",
			},
			setup: func(t *testing.T, root string) {
				t.Helper()
				skipWithoutPermissions(t)
				lockPath(t, filepath.Join(root, "z", ".gitignore"), 0o644)
			},
		},
	}

	for _, tc := range cases {
		for _, combination := range differentialFlagCombinations {
			t.Run(tc.name+"/"+combination.name, func(t *testing.T) {
				root := t.TempDir()
				for path, content := range tc.files {
					createFileInPath(t, filepath.Join(root, path), []byte(content))
				}
				if len(tc.tracked) > 0 {
					repo, err := git.PlainInit(root, false)
					require.NoError(t, err)
					worktree, err := repo.Worktree()
					require.NoError(t, err)
					for _, tracked := range tc.tracked {
						_, err = worktree.Add(tracked)
						require.NoError(t, err)
					}
				}
				if tc.setup != nil {
					tc.setup(t, root)
				}

				assertSameAsLegacy(t, root, combination.flags, tc.extraRules...)
			})
		}
	}
}

func TestWalkFilteredFiles_WithoutRuleFilesAppliesOnlyDefaultAndExtraRules(t *testing.T) {
	root := t.TempDir()
	for path, content := range map[string]string{
		".git/config":   "x",
		".gitignore":    "src/\n",
		"src/a.js":      "x",
		"vendor/b.js":   "x",
		"vendor/c.tmp":  "x",
		"docs/guide.md": "x",
	} {
		createFileInPath(t, filepath.Join(root, path), []byte(content))
	}
	extraRules := []string{"**/vendor/**"}

	legacy := NewFileFilter(root, &log.Logger)
	rules, err := legacy.GetRules(nil)
	require.NoError(t, err)
	expected := drainFilteredFiles(t, legacy.GetFilteredFiles(legacy.GetAllFiles(), slices.Concat(extraRules, rules)))
	require.Contains(t, expected, filepath.Join(root, "src", "a.js"), ".gitignore must not be applied without rule files")
	require.NotContains(t, expected, filepath.Join(root, ".git", "config"))
	require.NotContains(t, expected, filepath.Join(root, "vendor", "b.js"))

	recorder := newMetricsRecorder(t)
	walk := NewFileFilter(root, &log.Logger, WithMetrics(recorder), WithExtraRules(extraRules))
	walkFiles, err := walk.WalkFilteredFiles()
	require.NoError(t, err)

	assert.ElementsMatch(t, expected, drainFilteredFiles(t, walkFiles))
	assert.NotContains(t, recordedMetrics(t, recorder)[metricVariantLegacy].ints, metricRulesBuildDurationMs,
		"without rule files there are no rules to build, so no tree walk to time")
}

func TestWalkFilteredFiles_MatchesLegacyOnRandomTrees(t *testing.T) {
	const iterations = 300
	folderNames := []string{"node_modules", "dist", "src", "a", "X", "keep", "a(b)", "ab"}
	fileNames := []string{"a.js", "keep.js", "b.log", "c.tmp", "keep", "x.config.js"}
	ruleLines := []string{"node_modules/", "dist/", "*.log", "!keep.js", "!*.log", "X/**", "!X/keep", "!node_modules/", "/a", "!keep", "**/dist/**", "*.tmp", "!a/keep.js", "ab/"}
	rng := rand.New(rand.NewPCG(1, 2))

	randomTree := func() map[string]string {
		files := map[string]string{}
		var addFolder func(dir string, depth int)
		addFolder = func(dir string, depth int) {
			if depth > 3 {
				return
			}
			for range rng.IntN(3) + 1 {
				folder := filepath.Join(dir, folderNames[rng.IntN(len(folderNames))])
				if _, isFile := files[folder]; isFile {
					continue
				}
				for range rng.IntN(4) + 1 {
					files[filepath.Join(folder, fileNames[rng.IntN(len(fileNames))])] = "x"
				}
				if rng.Float64() < 0.3 {
					ruleFile := ".gitignore"
					if rng.Float64() < 0.5 {
						ruleFile = ".dcignore"
					}
					lines := make([]string, rng.IntN(4)+1)
					for i := range lines {
						lines[i] = ruleLines[rng.IntN(len(ruleLines))]
					}
					files[filepath.Join(folder, ruleFile)] = strings.Join(lines, "\n") + "\n"
				}
				addFolder(folder, depth+1)
			}
		}
		addFolder("", 0)
		return files
	}

	for i := range iterations {
		files := randomTree()
		for _, combination := range differentialFlagCombinations {
			t.Run(fmt.Sprintf("tree=%d/%s", i, combination.name), func(t *testing.T) {
				root := t.TempDir()
				for path, content := range files {
					if isFolderIn(files, path) {
						continue
					}
					createFileInPath(t, filepath.Join(root, path), []byte(content))
				}
				t.Cleanup(func() {
					if t.Failed() {
						t.Logf("tree: %q", files)
					}
				})

				assertSameAsLegacy(t, root, combination.flags)
			})
		}
	}
}

// isFolderIn reports whether a random tree also uses path as a folder.
func isFolderIn(files map[string]string, path string) bool {
	prefix := path + string(filepath.Separator)
	for other := range files {
		if strings.HasPrefix(other, prefix) {
			return true
		}
	}
	return false
}

func TestCompileRuleMatcher_detectsNegationsLikeTheLibrary(t *testing.T) {
	for _, test := range []struct {
		line    string
		negated bool
	}{
		{line: "!a", negated: true},
		{line: " !a", negated: true},
		{line: "!a\r", negated: true},
		{line: "#!a", negated: false},
		{line: `\!a`, negated: false},
		{line: "a!", negated: false},
		{line: gitIgnoreGlobPrefix + "!a", negated: false},
	} {
		t.Run(fmt.Sprintf("%q", test.line), func(t *testing.T) {
			assert.Equal(t, test.negated, compileRuleMatcher([]string{test.line}).negations != nil)
		})
	}
}
