package utils

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertSameAsLegacy(t *testing.T, root string, flags map[string]bool) {
	t.Helper()

	cfg := newTestConfig(flags)
	ruleFiles := []string{".gitignore", ".dcignore", ".snyk"}

	// Legacy flow: GetRules + GetAllFiles + GetFilteredFiles
	legacy := NewFileFilter(root, &log.Logger, WithConfig(cfg))
	rules, err := legacy.GetRules(ruleFiles)
	if err != nil {
		// If legacy fails, new flow must also fail
		newFilter := NewFileFilter(root, &log.Logger, WithConfig(cfg), WithRuleFiles(ruleFiles))
		_, newErr := newFilter.WalkFilteredFiles()
		assert.Error(t, newErr, "new flow must error when legacy errors")
		return
	}

	legacyResult := rules
	legacyFiles := drainFilteredFiles(t, legacy.GetFilteredFiles(legacy.GetAllFiles(), legacyResult))

	// New flow: WalkFilteredFiles
	newFilter := NewFileFilter(root, &log.Logger, WithConfig(cfg), WithRuleFiles(ruleFiles))
	newCh, err := newFilter.WalkFilteredFiles()
	require.NoError(t, err, "WalkFilteredFiles must not error when legacy succeeds")
	newFiles := drainFilteredFiles(t, newCh)

	assert.ElementsMatch(t, legacyFiles, newFiles, "files must match legacy flow")
}

func TestWalkFilteredFiles_MatchesLegacy(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string               // path -> content
		tracked []string                        // relative paths to git track
		setup   func(t *testing.T, root string) // optional setup
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
			name: "newline in a file name inside an ignored folder",
			files: map[string]string{
				".gitignore":           "node_modules/\n",
				"node_modules/a\nb.js": "x",
				"node_modules/c.js":    "x",
			},
			setup: func(t *testing.T, root string) {
				t.Helper()
				if runtime.GOOS == "windows" {
					t.Skip("newlines in filenames not supported on Windows")
				}
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
				if runtime.GOOS == "windows" || os.Geteuid() == 0 {
					t.Skip("directory permissions not enforced")
				}
				locked := filepath.Join(root, "node_modules", "locked")
				require.NoError(t, os.Mkdir(locked, 0o755))
				require.NoError(t, os.Chmod(locked, 0o000))
				t.Cleanup(func() { assert.NoError(t, os.Chmod(locked, 0o755)) })
			},
		},
		{
			name: "unreadable top-level folder plus nested rules",
			files: map[string]string{
				"z/.gitignore": "token.txt\n",
				"z/token.txt":  "x",
				"z/code.ts":    "x",
			},
			setup: func(t *testing.T, root string) {
				t.Helper()
				if runtime.GOOS == "windows" || os.Geteuid() == 0 {
					t.Skip("directory permissions not enforced")
				}
				locked := filepath.Join(root, "a-locked")
				require.NoError(t, os.Mkdir(locked, 0o755))
				require.NoError(t, os.Chmod(locked, 0o000))
				t.Cleanup(func() { assert.NoError(t, os.Chmod(locked, 0o755)) })
			},
		},
		{
			name: "unreadable rule file",
			files: map[string]string{
				".gitignore":   "ignored/\n",
				"z/.gitignore": "token.txt\n",
				"z/code.ts":    "x",
			},
			setup: func(t *testing.T, root string) {
				t.Helper()
				if runtime.GOOS == "windows" || os.Geteuid() == 0 {
					t.Skip("directory permissions not enforced")
				}
				unreadableRules := filepath.Join(root, "z", ".gitignore")
				require.NoError(t, os.Chmod(unreadableRules, 0o000))
				t.Cleanup(func() { assert.NoError(t, os.Chmod(unreadableRules, 0o644)) })
			},
		},
	}

	flagCombinations := []struct {
		name  string
		flags map[string]bool
	}{
		{
			name: "tracked=false,metachar=false",
			flags: map[string]bool{
				FF_GITIGNORE_RESPECT_TRACKED_FILES: false,
				FF_FILE_FILTER_METACHARACTER_FIX:   false,
			},
		},
		{
			name: "tracked=false,metachar=true",
			flags: map[string]bool{
				FF_GITIGNORE_RESPECT_TRACKED_FILES: false,
				FF_FILE_FILTER_METACHARACTER_FIX:   true,
			},
		},
		{
			name: "tracked=true,metachar=false",
			flags: map[string]bool{
				FF_GITIGNORE_RESPECT_TRACKED_FILES: true,
				FF_FILE_FILTER_METACHARACTER_FIX:   false,
			},
		},
		{
			name: "tracked=true,metachar=true",
			flags: map[string]bool{
				FF_GITIGNORE_RESPECT_TRACKED_FILES: true,
				FF_FILE_FILTER_METACHARACTER_FIX:   true,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, fc := range flagCombinations {
				t.Run(fc.name, func(t *testing.T) {
					root := t.TempDir()

					// Create files
					for path, content := range tc.files {
						createFileInPath(t, filepath.Join(root, path), []byte(content))
					}

					// Initialize git repo if needed
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

					assertSameAsLegacy(t, root, fc.flags)
				})
			}
		})
	}
}

func TestWalkFilteredFiles_MatchesLegacyOnRandomTrees(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))

	folderNames := []string{"node_modules", "dist", "src", "a", "X", "keep", "a(b)", "ab"}
	fileNames := []string{"a.js", "keep.js", "b.log", "c.tmp", "keep", "x.config.js"}
	ruleLines := []string{"node_modules/", "dist/", "*.log", "!keep.js", "!*.log", "X/**", "!X/keep", "!node_modules/", "/a", "!keep", "**/dist/**", "*.tmp", "!a/keep.js", "ab/"}

	flagCombinations := []struct {
		name  string
		flags map[string]bool
	}{
		{
			name: "tracked=false,metachar=false",
			flags: map[string]bool{
				FF_GITIGNORE_RESPECT_TRACKED_FILES: false,
				FF_FILE_FILTER_METACHARACTER_FIX:   false,
			},
		},
		{
			name: "tracked=false,metachar=true",
			flags: map[string]bool{
				FF_GITIGNORE_RESPECT_TRACKED_FILES: false,
				FF_FILE_FILTER_METACHARACTER_FIX:   true,
			},
		},
		{
			name: "tracked=true,metachar=false",
			flags: map[string]bool{
				FF_GITIGNORE_RESPECT_TRACKED_FILES: true,
				FF_FILE_FILTER_METACHARACTER_FIX:   false,
			},
		},
		{
			name: "tracked=true,metachar=true",
			flags: map[string]bool{
				FF_GITIGNORE_RESPECT_TRACKED_FILES: true,
				FF_FILE_FILTER_METACHARACTER_FIX:   true,
			},
		},
	}

	for iter := 0; iter < 300; iter++ {
		for _, fc := range flagCombinations {
			root := t.TempDir()
			files := make(map[string]string)
			usedPaths := make(map[string]bool)

			// Generate random tree
			var buildTree func(prefix string, depth int)
			buildTree = func(prefix string, depth int) {
				if depth > 3 {
					return
				}

				numFolders := rng.IntN(3) + 1
				for i := 0; i < numFolders; i++ {
					folderName := folderNames[rng.IntN(len(folderNames))]
					folderPath := filepath.Join(prefix, folderName)

					// Skip if this path is already used
					if usedPaths[folderPath] {
						continue
					}
					usedPaths[folderPath] = true

					// Random files in folder
					numFiles := rng.IntN(4) + 1
					for j := 0; j < numFiles; j++ {
						fileName := fileNames[rng.IntN(len(fileNames))]
						filePath := filepath.Join(folderPath, fileName)

						// Skip if this path is already used (avoids file/dir collisions)
						if usedPaths[filePath] {
							continue
						}
						usedPaths[filePath] = true
						files[filePath] = "x"
					}

					// Random .gitignore/.dcignore in some folders
					if rng.Float64() < 0.3 {
						ruleFile := ".gitignore"
						if rng.Float64() < 0.5 {
							ruleFile = ".dcignore"
						}

						rulePath := filepath.Join(folderPath, ruleFile)
						// Skip if this path is already used
						if !usedPaths[rulePath] {
							usedPaths[rulePath] = true
							numLines := rng.IntN(4) + 1
							lines := make([]string, numLines)
							for k := 0; k < numLines; k++ {
								lines[k] = ruleLines[rng.IntN(len(ruleLines))]
							}
							files[rulePath] = strings.Join(lines, "\n") + "\n"
						}
					}

					// Recurse
					buildTree(folderPath, depth+1)
				}
			}

			buildTree(".", 0)

			// Create all files
			for path, content := range files {
				createFileInPath(t, filepath.Join(root, path), []byte(content))
			}

			t.Run(fmt.Sprintf("iter=%d/%s", iter, fc.name), func(t *testing.T) {
				assertSameAsLegacy(t, root, fc.flags)
			})

			// If test failed, log the generated tree
			if t.Failed() {
				t.Logf("Generated tree for iteration %d:\n%v", iter, files)
			}
		}
	}
}

func TestRuleMatcher_negationsMatchLibrary(t *testing.T) {
	tests := []struct {
		line      string
		isNegated bool
	}{
		{"!a", true},
		{" !a", true},
		{"!a\r", true},
		{"#!a", false},
		{"\\!a", false},
		{"a!", false},
		{"#gitignore:!a", false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("line=%q", tt.line), func(t *testing.T) {
			matcher := compileRuleMatcher([]string{tt.line})
			if tt.isNegated {
				assert.NotNil(t, matcher.negations, "negations should not be nil for negated line %q", tt.line)
			} else {
				assert.Nil(t, matcher.negations, "negations should be nil for non-negated line %q", tt.line)
			}
		})
	}
}
