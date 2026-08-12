package utils

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/metrics"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

// newTestConfig builds an in-memory configuration with the given boolean feature flags preset.
func newTestConfig(flags map[string]bool) configuration.Configuration {
	config := configuration.NewWithOpts()
	for key, value := range flags {
		config.Set(key, value)
	}
	return config
}

type fileFilterTestCase struct {
	// the name of the test case. Will be used as the test name in t.Run()
	name string
	// path to the repo to be scanned
	repoPath string
	// ruleFiles lists the valid filenames to extract rules from
	ruleFiles []string
	// map of filenames to extract filter rules from. Key is the relative path to the repoPath, value is the content of the file.
	ruleFilesContent map[string]string
	// will assert that these filesToFilter are in the list of filesToFilter to be uploaded. Files paths are relative to the repoPath
	expectedFiles []string
	// filesToFilter lists files in the filesystem that match the expectedGlobs. File paths are relative to the repoPath
	filesToFilter []string
}

func TestFileFilter_GetAllFiles(t *testing.T) {
	t.Run("gets all filesToFilter for path", func(t *testing.T) {
		tempDir := t.TempDir()
		tempFile1 := filepath.Join(tempDir, "test1.ts")
		createFileInPath(t, tempFile1, []byte{})
		tempFile2 := filepath.Join(tempDir, "test2.ts")
		createFileInPath(t, tempFile2, []byte{})

		fileFilter := NewFileFilter(tempDir, &log.Logger)
		actualFiles := fileFilter.GetAllFiles()
		expectedFiles := []string{tempFile1, tempFile2}

		var actualFilesChanLen int
		for actualFile := range actualFiles {
			actualFilesChanLen++
			assert.Contains(t, expectedFiles, actualFile)
		}
		assert.Equal(t, len(expectedFiles), actualFilesChanLen)
	})

	t.Run("handles empty path", func(t *testing.T) {
		fileFilter := NewFileFilter("", &log.Logger)
		actualFiles := fileFilter.GetAllFiles()

		var actualFilesChanLen int
		for range actualFiles {
			actualFilesChanLen++
		}
		assert.Equal(t, 0, actualFilesChanLen)
	})
}

func TestFileFilter_GetRules_gitignoreFormat(t *testing.T) {
	// create temp filesystem
	tempDir := t.TempDir()
	tempFile1 := filepath.Join(tempDir, "test1.ts")
	createFileInPath(t, tempFile1, []byte{})
	tempFile2 := filepath.Join(tempDir, "test2.ts")
	createFileInPath(t, tempFile2, []byte{})

	t.Run("includes default rules", func(t *testing.T) {
		// create fileFilter
		fileFilter := NewFileFilter(tempDir, &log.Logger)
		actualRules, err := fileFilter.GetRules([]string{})
		assert.NoError(t, err)

		assert.ElementsMatch(t, fileFilter.defaultRules, actualRules)
	})

	t.Run("gets ignore rules for path", func(t *testing.T) {
		// adds ignore file to filesystem
		ignoreFile := filepath.Join(tempDir, ".gitignore")
		createFileInPath(t, ignoreFile, []byte("test1.ts\n"))

		// create fileFilter
		ruleFiles := []string{".gitignore"}
		fileFilter := NewFileFilter(tempDir, &log.Logger)
		actualRules, err := fileFilter.GetRules(ruleFiles)
		assert.NoError(t, err)

		// create expected rules
		expectedRules := append(
			[]string{
				fmt.Sprintf("%s/**/test1.ts/**", filepath.ToSlash(tempDir)), // apply ignore in subDirs
				fmt.Sprintf("%s/**/test1.ts", filepath.ToSlash(tempDir)),    // apply ignore in curDir
			},
			fileFilter.defaultRules...,
		)

		assert.ElementsMatch(t, expectedRules, actualRules)
	})

	t.Run("only gets ignore rules from valid files", func(t *testing.T) {
		// adds ignore file to filesystem
		ignoreFile := filepath.Join(tempDir, ".gitignore")
		createFileInPath(t, ignoreFile, []byte("test1.ts\n"))

		// adds a similarly named ignore file to filesystem
		almostAnIgnoreFile := filepath.Join(tempDir, "almost.gitignore.go")
		createFileInPath(t, almostAnIgnoreFile, []byte("package main\n import \"fmt\"\n func main() { fmt.Println(\"hello world\") }"))

		// create fileFilter
		ruleFiles := []string{".gitignore"}
		fileFilter := NewFileFilter(tempDir, &log.Logger)
		actualRules, err := fileFilter.GetRules(ruleFiles)
		assert.NoError(t, err)

		// create expected rules
		expectedRules := append(
			[]string{
				fmt.Sprintf("%s/**/test1.ts/**", filepath.ToSlash(tempDir)), // apply ignore in subDirs
				fmt.Sprintf("%s/**/test1.ts", filepath.ToSlash(tempDir)),    // apply ignore in curDir
			},
			fileFilter.defaultRules...,
		)

		assert.ElementsMatch(t, expectedRules, actualRules)
	})
}

func TestFileFilter_GetRules_dotSnykFormat(t *testing.T) {
	// create temp filesystem
	tempDir := t.TempDir()
	tempFile1 := "test1.ts"
	tempFilePath1 := filepath.Join(tempDir, tempFile1)
	createFileInPath(t, tempFilePath1, []byte{})
	tempFile2 := "test2.ts"
	tempFilePath2 := filepath.Join(tempDir, tempFile2)
	createFileInPath(t, tempFilePath2, []byte{})

	t.Run("gets ignore rules for .snyk excludes", func(t *testing.T) {
		// adds .snyk ignore file to filesystem
		ignoreFile := filepath.Join(tempDir, ".snyk")
		ignoreFileContent := fmt.Sprintf(`# Snyk (https://snyk.io) policy file
version: v1.25.1
ignore: {}
exclude:
  code:
    - %s
    - %s:
        reason: testing valid expiry
        expires: 3026-01-01T00:00:00Z
        created: 2000-01-01T00:00:00Z
`, tempFile1, tempFile2)
		createFileInPath(t, ignoreFile, []byte(ignoreFileContent))

		// create fileFilter
		ruleFiles := []string{".snyk"}
		fileFilter := NewFileFilter(tempDir, &log.Logger)
		actualRules, err := fileFilter.GetRules(ruleFiles)
		assert.NoError(t, err)

		// create expected rules
		expectedRules := append(
			[]string{
				fmt.Sprintf("%s/**/%s/**", filepath.ToSlash(tempDir), tempFile1),
				fmt.Sprintf("%s/**/%s", filepath.ToSlash(tempDir), tempFile1),
				fmt.Sprintf("%s/**/%s/**", filepath.ToSlash(tempDir), tempFile2),
				fmt.Sprintf("%s/**/%s", filepath.ToSlash(tempDir), tempFile2),
			},
			fileFilter.defaultRules...,
		)

		assert.ElementsMatch(t, expectedRules, actualRules)
	})

	t.Run("does not apply ignore rules for expired .snyk excludes", func(t *testing.T) {
		// adds .snyk ignore file to filesystem
		ignoreFile := filepath.Join(tempDir, ".snyk")
		ignoreFileContent := fmt.Sprintf(`# Snyk (https://snyk.io) policy file
version: v1.25.1
ignore: {}
exclude:
  code:
    - %s:
        reason: testing valid expiry
        expires: 3026-01-01T00:00:00Z
        created: 2000-01-01T00:00:00Z
  global:
    - %s:
        reason: testing expired ignore
        expires: Fri, 01 Jan 1999 00:00:00 +0000
        created: Mon, 01 Jan 1990 00:00:00 +0000
`, tempFile1, tempFile2)
		createFileInPath(t, ignoreFile, []byte(ignoreFileContent))

		// create fileFilter
		ruleFiles := []string{".snyk"}
		fileFilter := NewFileFilter(tempDir, &log.Logger)
		actualRules, err := fileFilter.GetRules(ruleFiles)
		assert.NoError(t, err)

		// create expected rules
		expectedRules := append(
			[]string{
				fmt.Sprintf("%s/**/test1.ts/**", filepath.ToSlash(tempDir)),
				fmt.Sprintf("%s/**/test1.ts", filepath.ToSlash(tempDir)),
			},
			fileFilter.defaultRules...,
		)

		assert.ElementsMatch(t, expectedRules, actualRules)
	})
}

func TestFileFilter_GetRules_dotSnykSections(t *testing.T) {
	tempDir := t.TempDir()
	codeFile := "code.ts"
	globalFile := "global.ts"
	secretsFile := "secrets.ts"
	// customFile lives under a section this package defines no constant for, to
	// exercise the map-based decode that lets callers opt into arbitrary sections.
	customFile := "custom.ts"
	createFileInPath(t, filepath.Join(tempDir, codeFile), []byte{})
	createFileInPath(t, filepath.Join(tempDir, globalFile), []byte{})
	createFileInPath(t, filepath.Join(tempDir, secretsFile), []byte{})
	createFileInPath(t, filepath.Join(tempDir, customFile), []byte{})

	snykContent := fmt.Sprintf(`exclude:
  code:
    - %s
  global:
    - %s
  secrets:
    - %s
  newsection:
    - %s
`, codeFile, globalFile, secretsFile, customFile)

	// globsFor returns the expected glob patterns for a given filename.
	globsFor := func(file string) []string {
		return []string{
			fmt.Sprintf("%s/**/%s/**", filepath.ToSlash(tempDir), file),
			fmt.Sprintf("%s/**/%s", filepath.ToSlash(tempDir), file),
		}
	}

	tests := []struct {
		name          string
		options       []FileFilterOption
		expectedFiles []string
	}{
		{
			name:          "defaults to code and global sections",
			options:       nil,
			expectedFiles: []string{codeFile, globalFile},
		},
		{
			name:          "applies only the requested section",
			options:       []FileFilterOption{WithDotSnykSections([]DotSnykExcludeSectionName{DotSnykExcludeSecrets})},
			expectedFiles: []string{secretsFile},
		},
		{
			name:          "applies all sections when requested",
			options:       []FileFilterOption{WithDotSnykSections([]DotSnykExcludeSectionName{DotSnykExcludeCode, DotSnykExcludeGlobal, DotSnykExcludeSecrets})},
			expectedFiles: []string{codeFile, globalFile, secretsFile},
		},
		{
			name:          "empty slice disables all .snyk exclusions",
			options:       []FileFilterOption{WithDotSnykSections([]DotSnykExcludeSectionName{})},
			expectedFiles: []string{},
		},
		{
			// no code change in file_filter.go is needed to support a new section
			name:          "supports sections without a predefined constant",
			options:       []FileFilterOption{WithDotSnykSections([]DotSnykExcludeSectionName{"newsection"})},
			expectedFiles: []string{customFile},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ignoreFile := filepath.Join(tempDir, ".snyk")
			createFileInPath(t, ignoreFile, []byte(snykContent))

			fileFilter := NewFileFilter(tempDir, &log.Logger, test.options...)
			actualRules, err := fileFilter.GetRules([]string{".snyk"})
			assert.NoError(t, err)

			var expectedRules []string
			for _, file := range test.expectedFiles {
				expectedRules = append(expectedRules, globsFor(file)...)
			}
			expectedRules = append(expectedRules, fileFilter.defaultRules...)

			assert.ElementsMatch(t, expectedRules, actualRules)
		})
	}

	t.Run("preserves code-before-global ordering by default", func(t *testing.T) {
		ignoreFile := filepath.Join(tempDir, ".snyk")
		createFileInPath(t, ignoreFile, []byte(snykContent))

		fileFilter := NewFileFilter(tempDir, &log.Logger)
		actualRules, err := fileFilter.GetRules([]string{".snyk"})
		assert.NoError(t, err)

		// strip default rules to compare only the .snyk-derived globs
		snykRules := actualRules[len(fileFilter.defaultRules):]
		expectedRules := append(globsFor(codeFile), globsFor(globalFile)...)
		assert.Equal(t, expectedRules, snykRules)
	})
}

// TestFileFilter_GetRules_dotSnykMalformedSection verifies that .snyk exclude
// sections are decoded independently: a section whose value is not a sequence
// (e.g. a stray scalar) is malformed and must be skipped without dropping the
// valid exclusions from other sections, and a malformed section a caller never
// opts into must be ignored entirely. In every case the valid code exclusion
// must survive.
func TestFileFilter_GetRules_dotSnykMalformedSection(t *testing.T) {
	tempDir := t.TempDir()
	codeFile := "code.ts"
	createFileInPath(t, filepath.Join(tempDir, codeFile), []byte{})

	// The code section is valid; global and secrets are malformed (scalars where a
	// sequence is expected).
	snykContent := fmt.Sprintf(`exclude:
  code:
    - %s
  global: not-a-list
  secrets: not-a-list
`, codeFile)
	createFileInPath(t, filepath.Join(tempDir, ".snyk"), []byte(snykContent))

	// globsFor returns the expected glob patterns for a given filename.
	globsFor := func(file string) []string {
		return []string{
			fmt.Sprintf("%s/**/%s/**", filepath.ToSlash(tempDir), file),
			fmt.Sprintf("%s/**/%s", filepath.ToSlash(tempDir), file),
		}
	}

	tests := []struct {
		name    string
		options []FileFilterOption
	}{
		{
			// code and global are both requested (the default); the malformed global
			// is skipped while the valid code exclusion still applies.
			name:    "malformed requested section is skipped, other requested sections still apply",
			options: nil,
		},
		{
			// only code is requested; the malformed secrets section is not parsed.
			name:    "malformed non-requested section is ignored",
			options: []FileFilterOption{WithDotSnykSections([]DotSnykExcludeSectionName{DotSnykExcludeCode})},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fileFilter := NewFileFilter(tempDir, &log.Logger, test.options...)
			actualRules, err := fileFilter.GetRules([]string{".snyk"})
			assert.NoError(t, err)

			expectedRules := append(globsFor(codeFile), fileFilter.defaultRules...)
			assert.ElementsMatch(t, expectedRules, actualRules,
				"a malformed section must not drop valid exclusions from other sections")
		})
	}
}

func TestFileFilter_GetFilteredFiles(t *testing.T) {
	cases := testCases(t)
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			setupTestFileSystem(t, testCase)

			fileFilter := NewFileFilter(testCase.repoPath, &log.Logger)

			files := fileFilter.GetAllFiles()

			globs, err := fileFilter.GetRules(testCase.ruleFiles)
			assert.NoError(t, err)

			filteredFiles := fileFilter.GetFilteredFiles(files, globs)
			expectedFilePaths := make([]string, 0)
			for _, file := range testCase.expectedFiles {
				expectedFilePaths = append(expectedFilePaths, filepath.Join(testCase.repoPath, file))
			}

			for filteredFile := range filteredFiles {
				assert.Contains(t, expectedFilePaths, filteredFile)
			}

			t.Run("2nd call should return the same filesToFilter", func(t *testing.T) {
				filteredFiles := fileFilter.GetFilteredFiles(files, globs)
				for filteredFile := range filteredFiles {
					assert.Contains(t, expectedFilePaths, filteredFile)
				}
			})
		})
	}
}

// TestFileFilter_GetFilteredFiles_pathWithRegexMetaChars checks that ignore rules still
// apply when the project path contains regex metacharacters (CLI-1648).
func TestFileFilter_GetFilteredFiles_pathWithRegexMetaChars(t *testing.T) {
	metaCharDirs := []string{
		"OneDrive - Foobar (Team1)", // parentheses + spaces (customer's path shape)
		"Program Files (x86)",       // parentheses + spaces
		"a+b",                       // plus
		"c{d}",                      // braces (not a valid quantifier)
		"backup{2}",                 // braces forming a valid regex quantifier
		"a^b",                       // caret
		"a|b",                       // pipe / alternation
		"a$b",                       // dollar
		"a*b",                       // glob wildcard in the path
		"a[b]c",                     // glob character class in the path
		"a?b",                       // glob single-char wildcard in the path
		"a\\b",                      // literal backslash (legal on unix, illegal on windows)
		"first.last",                // dot in path (e.g. C:\Users\first.last)
		"Users/first.last/OneDrive - Foobar (Team1)/docs", // combined: dot + parens + spaces
	}

	// Characters Windows does not allow in file/directory names, so such paths cannot exist
	// there and the corresponding cases are skipped on Windows.
	const windowsIllegalChars = `<>:"/\|?*`

	for _, dirName := range metaCharDirs {
		t.Run(dirName, func(t *testing.T) {
			if runtime.GOOS == "windows" && strings.ContainsAny(dirName, windowsIllegalChars) {
				t.Skipf("%q contains characters not allowed in Windows paths", dirName)
			}
			base := filepath.Join(t.TempDir(), dirName, "repo")
			nodeModulesFile := filepath.Join(base, "node_modules", "lib", "index.js")
			appFile := filepath.Join(base, "app.js")
			gitignore := filepath.Join(base, ".gitignore")
			createFileInPath(t, nodeModulesFile, []byte("x"))
			createFileInPath(t, appFile, []byte("x"))
			createFileInPath(t, gitignore, []byte("node_modules\n"))

			config := newTestConfig(map[string]bool{FF_FILE_FILTER_METACHARACTER_FIX: true})
			fileFilter := NewFileFilter(base, &log.Logger, WithConfig(config))
			globs, err := fileFilter.GetRules([]string{".gitignore"})
			assert.NoError(t, err)

			var filtered []string
			for f := range fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), globs) {
				filtered = append(filtered, f)
			}

			assert.Contains(t, filtered, appFile, "app.js should be scanned")
			assert.NotContains(t, filtered, nodeModulesFile, "node_modules must be excluded")
		})
	}
}

type ignoreRuleScenario struct {
	name string
	// scanRootName, when set, roots the FileFilter at t.TempDir()/scanRootName instead of
	// t.TempDir(). This exercises metacharacters in the scan root itself, not just in
	// intermediate directories. files/excluded/kept remain relative to that root.
	scanRootName string
	// files maps a slash-separated path (relative to the scan root) to its content.
	files map[string]string
	// ruleFiles lists the valid ignore filenames to extract rules from.
	ruleFiles []string
	// excluded/kept list slash-separated paths that must / must not be filtered out.
	excluded []string
	kept     []string
	// windowsOnly skips the scenario on non-Windows platforms.
	windowsOnly bool
	// skipOnWindows skips the scenario on Windows, for paths that contain characters Windows
	// does not allow in file/directory names (e.g. "|", "\\").
	skipOnWindows bool
}

// TestFileFilter_GetFilteredFiles_ignoreRuleScenarios is the behavioral regression net for the
// special-character-path fix (CLI-1648). Each scenario builds a filesystem (including ignore
// files), filters it, then asserts which files survive.
//
// This is deliberately NOT a full gitignore conformance suite: go-gitignore has known gaps we
// cannot fix here (the "?" single-char wildcard, escaped trailing spaces, full POSIX character
// classes). We only cover behavior the library supports and that the fix must preserve.
func TestFileFilter_GetFilteredFiles_ignoreRuleScenarios(t *testing.T) {
	scenarios := []ignoreRuleScenario{
		// --- Existing behaviors (kept) ---
		{
			name: "negated character class rule keeps working",
			files: map[string]string{
				".gitignore":      "cache[^S]\n",
				"cache1/index.js": "x", // matches cache[^S]
				"cacheS/index.js": "x", // excluded from the negated class
				"app.js":          "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"cache1/index.js"},
			kept:      []string{"cacheS/index.js", "app.js"},
		},
		{
			name: "ignore file in dir with regex metacharacters",
			files: map[string]string{
				"my (dir)/.gitignore": "secret.txt\n",
				"my (dir)/secret.txt": "x",
				"my (dir)/keep.txt":   "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"my (dir)/secret.txt"},
			kept:      []string{"my (dir)/keep.txt"},
		},
		{
			name: "deeply nested ignore file with metacharacters at every level",
			files: map[string]string{
				"a (1)/b [2]/c +3/.gitignore": "secret.txt\n",
				"a (1)/b [2]/c +3/secret.txt": "x",
				"a (1)/b [2]/c +3/keep.txt":   "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"a (1)/b [2]/c +3/secret.txt"},
			kept:      []string{"a (1)/b [2]/c +3/keep.txt"},
		},
		{
			name: "nested rule is scoped to its own directory",
			files: map[string]string{
				"sub (x)/.gitignore": "only.txt\n",
				"sub (x)/only.txt":   "x",
				"other/only.txt":     "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"sub (x)/only.txt"},
			kept:      []string{"other/only.txt"},
		},
		{
			name: "directory rule excludes all contents at any depth",
			files: map[string]string{
				".gitignore":           "build/\n",
				"build/out.js":         "x",
				"build/nested/deep.js": "x",
				"src/app.js":           "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"build/out.js", "build/nested/deep.js"},
			kept:      []string{"src/app.js"},
		},

		// --- A. Special-character scan roots (customer bug family) ---
		{
			name:         "scan root with parentheses and spaces",
			scanRootName: "OneDrive - Foobar (Team1)",
			files: map[string]string{
				".gitignore":                "node_modules\n",
				"node_modules/lib/index.js": "x",
				"app.js":                    "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"node_modules/lib/index.js"},
			kept:      []string{"app.js"},
		},
		{
			name:         "scan root with dot",
			scanRootName: "first.last",
			files: map[string]string{
				".gitignore":                "node_modules\n",
				"node_modules/lib/index.js": "x",
				"app.js":                    "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"node_modules/lib/index.js"},
			kept:      []string{"app.js"},
		},
		{
			name:         "scan root combined customer shape",
			scanRootName: "first.last/OneDrive - Foobar (Team1)",
			files: map[string]string{
				".gitignore":                "node_modules\n",
				"node_modules/lib/index.js": "x",
				"app.js":                    "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"node_modules/lib/index.js"},
			kept:      []string{"app.js"},
		},
		{
			name:         "scan root with plus and braces",
			scanRootName: "a+b/c{d}",
			files: map[string]string{
				".gitignore":                "node_modules\n",
				"node_modules/lib/index.js": "x",
				"app.js":                    "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"node_modules/lib/index.js"},
			kept:      []string{"app.js"},
		},
		{
			name:          "scan root with caret dollar and pipe",
			scanRootName:  "a^b/a$b/a|b", // "|" is illegal on Windows
			skipOnWindows: true,
			files: map[string]string{
				".gitignore":                "node_modules\n",
				"node_modules/lib/index.js": "x",
				"app.js":                    "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"node_modules/lib/index.js"},
			kept:      []string{"app.js"},
		},
		{
			name:          "scan root with backslash", // "\" is illegal on Windows
			scanRootName:  "a\\b",
			skipOnWindows: true,
			files: map[string]string{
				".gitignore":                "node_modules\n",
				"node_modules/lib/index.js": "x",
				"app.js":                    "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"node_modules/lib/index.js"},
			kept:      []string{"app.js"},
		},

		// --- B. gitignore rule variations (library-supported only) ---
		{
			name: "glob star matches extension",
			files: map[string]string{
				".gitignore": "*.log\n",
				"a.log":      "x",
				"a.txt":      "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"a.log"},
			kept:      []string{"a.txt"},
		},
		{
			name: "leading slash anchors to root",
			files: map[string]string{
				".gitignore":        "/root-only.txt\n",
				"root-only.txt":     "x",
				"sub/root-only.txt": "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"root-only.txt"},
			kept:      []string{"sub/root-only.txt"},
		},
		{
			name: "trailing slash excludes directory contents",
			files: map[string]string{
				".gitignore":   "logs/\n",
				"logs/a.txt":   "x",
				"logs/b/c.txt": "x",
				"logsx.txt":    "x", // sibling whose name only shares the stem is kept
				"src/app.js":   "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"logs/a.txt", "logs/b/c.txt"},
			kept:      []string{"logsx.txt", "src/app.js"},
		},
		{
			name: "nested path rule scoped to that path",
			files: map[string]string{
				".gitignore":     "src/gen/\n",
				"src/gen/g.js":   "x",
				"other/gen/g.js": "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"src/gen/g.js"},
			kept:      []string{"other/gen/g.js"},
		},
		{
			name: "double star matches at multiple depths",
			files: map[string]string{
				".gitignore":        "**/dist\n",
				"dist/a.js":         "x",
				"pkg/dist/b.js":     "x",
				"pkg/sub/dist/c.js": "x",
				"src/app.js":        "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"dist/a.js", "pkg/dist/b.js", "pkg/sub/dist/c.js"},
			kept:      []string{"src/app.js"},
		},
		{
			name: "negation re-includes a file",
			files: map[string]string{
				".gitignore": "*.log\n!keep.log\n",
				"a.log":      "x",
				"keep.log":   "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"a.log"},
			kept:      []string{"keep.log"},
		},
		{
			name: "comments and blank lines are ignored",
			files: map[string]string{
				".gitignore":                "# a comment\n\nnode_modules\n\n# trailing comment\n",
				"node_modules/lib/index.js": "x",
				"app.js":                    "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"node_modules/lib/index.js"},
			kept:      []string{"app.js"},
		},

		// --- C. Ignore-file-format variations ---
		{
			name: "dcignore file is honored",
			files: map[string]string{
				".dcignore":                 "node_modules\n",
				"node_modules/lib/index.js": "x",
				"app.js":                    "x",
			},
			ruleFiles: []string{".dcignore"},
			excluded:  []string{"node_modules/lib/index.js"},
			kept:      []string{"app.js"},
		},
		{
			name: "snyk global exclude (customer file)",
			files: map[string]string{
				".snyk":                     "# Snyk (https://snyk.io) policy file\nversion: v1.25.1\nexclude:\n  global:\n    - node_modules\n",
				"node_modules/lib/index.js": "x",
				"app.js":                    "x",
			},
			ruleFiles: []string{".snyk"},
			excluded:  []string{"node_modules/lib/index.js"},
			kept:      []string{"app.js"},
		},
		{
			name: "snyk code exclude",
			files: map[string]string{
				".snyk":       "version: v1.25.1\nexclude:\n  code:\n    - dist\n",
				"dist/out.js": "x",
				"app.js":      "x",
			},
			ruleFiles: []string{".snyk"},
			excluded:  []string{"dist/out.js"},
			kept:      []string{"app.js"},
		},
		{
			name: "gitignore and snyk applied together",
			files: map[string]string{
				".gitignore":                "node_modules\n",
				".snyk":                     "version: v1.25.1\nexclude:\n  global:\n    - dist\n",
				"node_modules/lib/index.js": "x",
				"dist/out.js":               "x",
				"app.js":                    "x",
			},
			ruleFiles: []string{".gitignore", ".snyk"},
			excluded:  []string{"node_modules/lib/index.js", "dist/out.js"},
			kept:      []string{"app.js"},
		},
		{
			name: "nested gitignore files scope independently",
			files: map[string]string{
				".gitignore":     "root.txt\n",
				"root.txt":       "x",
				"pkg/.gitignore": "pkg.txt\n",
				"pkg/pkg.txt":    "x",
				"pkg/root.txt":   "x", // root rule also applies here (matches at any level)
				"pkg/keep.txt":   "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"root.txt", "pkg/pkg.txt", "pkg/root.txt"},
			kept:      []string{"pkg/keep.txt"},
		},

		// --- C2. Special characters in the ignore rule pattern itself ---
		// git treats parentheses/spaces in a gitignore pattern as literal (fnmatch), so a folder
		// literally named "build (old)" should be excluded. These currently fail because the
		// rule side only escapes "$"; regex metacharacters in the rule reach go-gitignore and are
		// interpreted as regex. Documents the gap mirror of the base-path fix (CLI-1648).
		{
			name: "gitignore rule with parentheses and spaces",
			files: map[string]string{
				".gitignore":         "build (old)/\n",
				"build (old)/out.js": "x",
				"build/keep.js":      "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"build (old)/out.js"},
			kept:      []string{"build/keep.js"},
		},
		{
			name: "snyk rule with parentheses and spaces",
			files: map[string]string{
				".snyk":              "version: v1.25.1\nexclude:\n  global:\n    - build (old)\n",
				"build (old)/out.js": "x",
				"build/keep.js":      "x",
			},
			ruleFiles: []string{".snyk"},
			excluded:  []string{"build (old)/out.js"},
			kept:      []string{"build/keep.js"},
		},
		{
			// Guards every character in ruleRegexMetaChars except "|" (Windows-illegal, covered
			// below). Each metachar sits where leaving it unescaped would change the regex, so
			// dropping any one from the map makes go-gitignore mismatch the literal folder and
			// this case fails: "$" (anchor), "(c)" (group), "d+" (quantifier), "e{2}" (repetition).
			name: "gitignore rule with all windows-legal regex metacharacters",
			files: map[string]string{
				".gitignore":           "a$b(c)d+e{2}f/\n",
				"a$b(c)d+e{2}f/out.js": "x",
				"keep.js":              "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"a$b(c)d+e{2}f/out.js"},
			kept:      []string{"keep.js"},
		},
		{
			// "|" (alternation) is the only ruleRegexMetaChars entry illegal in Windows paths.
			name:          "gitignore rule with pipe metacharacter",
			skipOnWindows: true,
			files: map[string]string{
				".gitignore": "a|b/\n",
				"a|b/out.js": "x",
				"keep.js":    "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"a|b/out.js"},
			kept:      []string{"keep.js"},
		},

		// --- D. Path structure / real-world combinations ---
		{
			name: "deeply nested exclusion",
			files: map[string]string{
				".gitignore":          "build/\n",
				"build/a/b/c/deep.js": "x",
				"src/a/b/c/keep.js":   "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"build/a/b/c/deep.js"},
			kept:      []string{"src/a/b/c/keep.js"},
		},
		{
			name: "multiple siblings only matched one excluded",
			files: map[string]string{
				".gitignore": "temp\n",
				"temp/a.js":  "x",
				"tempx/a.js": "x",
				"atemp/a.js": "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"temp/a.js"},
			kept:      []string{"tempx/a.js", "atemp/a.js"},
		},
		{
			name: "monorepo node_modules at multiple levels",
			files: map[string]string{
				".gitignore":                             "node_modules\n",
				"node_modules/root/index.js":             "x",
				"packages/app/.gitignore":                "dist\n",
				"packages/app/node_modules/pkg/index.js": "x",
				"packages/app/dist/out.js":               "x",
				"packages/app/src/main.js":               "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded: []string{
				"node_modules/root/index.js",
				"packages/app/node_modules/pkg/index.js",
				"packages/app/dist/out.js",
			},
			kept: []string{"packages/app/src/main.js"},
		},

		// --- E. OS-specific: drive-letter scan root (Windows-only) ---
		{
			name:         "windows drive-letter scan root",
			windowsOnly:  true,
			scanRootName: "project",
			files: map[string]string{
				".gitignore":                "node_modules\n",
				"node_modules/lib/index.js": "x",
				"app.js":                    "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"node_modules/lib/index.js"},
			kept:      []string{"app.js"},
		},
	}

	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			if tc.windowsOnly && runtime.GOOS != "windows" {
				t.Skip("scenario only applies on Windows")
			}
			if tc.skipOnWindows && runtime.GOOS == "windows" {
				t.Skip("path contains characters not allowed on Windows")
			}

			root := t.TempDir()
			if tc.scanRootName != "" {
				root = filepath.Join(root, filepath.FromSlash(tc.scanRootName))
			}
			for p, content := range tc.files {
				createFileInPath(t, filepath.Join(root, filepath.FromSlash(p)), []byte(content))
			}

			config := newTestConfig(map[string]bool{FF_FILE_FILTER_METACHARACTER_FIX: true})
			fileFilter := NewFileFilter(root, &log.Logger, WithConfig(config))
			globs, err := fileFilter.GetRules(tc.ruleFiles)
			assert.NoError(t, err)

			kept := make(map[string]bool)
			for f := range fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), globs) {
				rel, relErr := filepath.Rel(root, f)
				assert.NoError(t, relErr)
				kept[filepath.ToSlash(rel)] = true
			}

			for _, e := range tc.excluded {
				assert.False(t, kept[e], "%q must be excluded", e)
			}
			for _, k := range tc.kept {
				assert.True(t, kept[k], "%q must be kept", k)
			}
		})
	}
}

// TestFileFilter_GetFilteredFiles_uncPaths covers UNC-style scan roots on Windows using real
// filesystem walks. t.TempDir() is a local path, so these derive a UNC-style root that points
// at the same files. They are Windows-only and skip gracefully when the derived root is not
// reachable (e.g. admin shares disabled). Unit-level UNC glob building is covered separately in
// TestParseIgnoreRuleToGlobs.
func TestFileFilter_GetFilteredFiles_uncPaths(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("UNC paths only exist on Windows")
	}

	// buildTree creates the standard node_modules/app.js/.gitignore tree under base and returns
	// the FileFilter rooted at scanRoot (which may be a UNC-style alias of base).
	assertFiltered := func(t *testing.T, scanRoot string, options ...FileFilterOption) {
		t.Helper()
		fileFilter := NewFileFilter(scanRoot, &log.Logger, options...)
		globs, err := fileFilter.GetRules([]string{".gitignore"})
		assert.NoError(t, err)

		kept := make(map[string]bool)
		for f := range fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), globs) {
			rel, relErr := filepath.Rel(scanRoot, f)
			assert.NoError(t, relErr)
			kept[filepath.ToSlash(rel)] = true
		}
		assert.False(t, kept["node_modules/lib/index.js"], "node_modules must be excluded")
		assert.True(t, kept["app.js"], "app.js must be kept")
	}

	makeTree := func(t *testing.T, base string) {
		t.Helper()
		createFileInPath(t, filepath.Join(base, ".gitignore"), []byte("node_modules\n"))
		createFileInPath(t, filepath.Join(base, "node_modules", "lib", "index.js"), []byte("x"))
		createFileInPath(t, filepath.Join(base, "app.js"), []byte("x"))
	}

	// driveToAdminShare converts "C:\path" to "\\localhost\C$\path" (and 127.0.0.1 variant).
	driveToAdminShare := func(host, p string) (string, bool) {
		if len(p) < 2 || p[1] != ':' {
			return "", false
		}
		drive := string(p[0])
		rest := strings.TrimPrefix(p[2:], `\`)
		return `\\` + host + `\` + drive + `$\` + rest, true
	}

	t.Run("genuine UNC via admin share", func(t *testing.T) {
		base := t.TempDir()
		makeTree(t, base)
		for _, host := range []string{"localhost", "127.0.0.1"} {
			unc, ok := driveToAdminShare(host, base)
			if !ok {
				t.Skipf("temp dir %q is not a drive-letter path", base)
			}
			if _, err := os.Stat(unc); err != nil {
				continue // admin share not reachable on this host, try the next
			}
			assertFiltered(t, unc)
			return
		}
		t.Skip("admin share (C$) not accessible; cannot exercise genuine UNC")
	})

	t.Run("extended-length prefix", func(t *testing.T) {
		base := t.TempDir()
		makeTree(t, base)
		extended := `\\?\` + base
		if _, err := os.Stat(extended); err != nil {
			t.Skipf("extended-length path not accessible: %v", err)
		}
		assertFiltered(t, extended)
	})

	t.Run("UNC with metacharacters via admin share", func(t *testing.T) {
		base := filepath.Join(t.TempDir(), "OneDrive - Foobar (Team1)")
		makeTree(t, base)
		unc, ok := driveToAdminShare("localhost", base)
		if !ok {
			t.Skipf("temp dir %q is not a drive-letter path", base)
		}
		if _, err := os.Stat(unc); err != nil {
			t.Skip("admin share (C$) not accessible; cannot exercise genuine UNC")
		}
		config := newTestConfig(map[string]bool{FF_FILE_FILTER_METACHARACTER_FIX: true})
		assertFiltered(t, unc, WithConfig(config))
	})
}

func BenchmarkFileFilter_GetFilteredFiles(b *testing.B) {
	b.Log("Creating filesystem...")
	rootDir := b.TempDir()
	filesPerFolder := 100
	folderDepth := 100
	err := generateFilesAndFolders(rootDir, filesPerFolder, folderDepth)
	assert.NoError(b, err)
	b.Log("Created file system")

	b.Log("Creating ignore file...")
	// create ignore file in root dir ignoring any file with name 'test1.ts'
	ignoreFile := filepath.Join(rootDir, ".gitignore")
	ruleFiles := []string{".gitignore"}

	gitIgnoreContent := ""
	for i := 1; i < folderDepth; i++ {
		gitIgnoreContent += fmt.Sprintf("folder_%d\n", i)
	}

	createFileInPath(b, ignoreFile, []byte(gitIgnoreContent))
	b.Log("Created ignore file")

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		fileFilter := NewFileFilter(rootDir, &log.Logger, WithThreadNumber(runtime.NumCPU()))

		b.StartTimer()
		globs, err := fileFilter.GetRules(ruleFiles)
		assert.NoError(b, err)
		filteredFiles := fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), globs)
		b.StopTimer()

		var actualFilteredFilesLen int
		for range filteredFiles {
			actualFilteredFilesLen++
		}

		assert.Equal(b, filesPerFolder+1, actualFilteredFilesLen) // +1 is the gitignore file
	}
}

func generateFilesAndFolders(rootDir string, filesPerFolder int, folderDepth int) error {
	for i := 0; i < folderDepth; i++ {
		currDir := filepath.Join(rootDir, fmt.Sprintf("folder_%d", i+1))
		if err := os.MkdirAll(currDir, 0755); err != nil {
			return err
		}

		for j := 0; j < filesPerFolder; j++ {
			filePath := filepath.Join(currDir, fmt.Sprintf("file_%d.txt", j+1))
			file, err := os.Create(filePath)
			if err != nil {
				return err
			}

			err = file.Close()
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func testCases(t *testing.T) []fileFilterTestCase {
	t.Helper()

	cases := []fileFilterTestCase{
		{
			name:      "filters by default rules when no matching rules are found",
			repoPath:  t.TempDir(),
			ruleFiles: []string{".gitignore"},
			ruleFilesContent: map[string]string{
				".gitignore": "some_random_thing_that_is_not_in_the_filesystem.json",
			},
			filesToFilter: []string{},
			expectedFiles: []string{"file1.java", "file2.java", ".gitignore"},
		},
		{
			name:             "filters by default rules when folder is empty",
			repoPath:         t.TempDir(),
			ruleFiles:        []string{},
			ruleFilesContent: map[string]string{},
			filesToFilter:    []string{},
			expectedFiles:    []string{},
		},
		{
			name:      "Respects ignore rules",
			repoPath:  t.TempDir(),
			ruleFiles: []string{".gitignore"},
			ruleFilesContent: map[string]string{
				".gitignore": "*.java\n",
			},
			filesToFilter: []string{"file1.java", "file2.java", "path/to/file3.java"},
			expectedFiles: []string{"file1.js", "path/to/file2.js", ".gitignore"},
		},
		{
			name:      "Respects default ignore rules",
			repoPath:  t.TempDir(),
			ruleFiles: []string{".gitignore"},
			ruleFilesContent: map[string]string{
				".gitignore": "",
			},
			filesToFilter: []string{},
			expectedFiles: []string{"file1.java", ".gitignore"},
		},
		{
			name:      "Respects negation rules",
			repoPath:  t.TempDir(),
			ruleFiles: []string{".gitignore"},
			ruleFilesContent: map[string]string{
				".gitignore": ("*.java\n") + ("!file1.java\n") + ("!path/to/file3.java\n"),
			},
			filesToFilter: []string{"file2.java"},
			expectedFiles: []string{"file1.java", "path/to/file3.java", ".gitignore"},
		},
		{
			name:      "Respects negation rules for filesToFilter inside folders",
			repoPath:  t.TempDir(),
			ruleFiles: []string{".gitignore"},
			ruleFilesContent: map[string]string{
				".gitignore": ("/path/*\n") + ("!/path/file2.java\n"),
			},
			filesToFilter: []string{"path/file3.java", "path/to/file5.java"},
			expectedFiles: []string{"file1.java", "path/file2.java", ".gitignore"},
		},
		{
			name:      "Nested ignore rules",
			repoPath:  t.TempDir(),
			ruleFiles: []string{".gitignore"},
			ruleFilesContent: map[string]string{
				".gitignore":         "*.java\n",
				"path/to/.gitignore": "*.js\n",
			},
			filesToFilter: []string{"file1.java", "path/to/file1.js", "path/to/nested/file2.js"},
			expectedFiles: []string{"file1.js", "file1.txt", "path/to/file2.txt", ".gitignore", "path/to/.gitignore"},
		},
		{
			name:      "Ignored folder with negation rules",
			repoPath:  t.TempDir(),
			ruleFiles: []string{".gitignore"},
			ruleFilesContent: map[string]string{
				".gitignore":   "/a/",
				"a/.gitignore": "!*.txt",
			},
			filesToFilter: []string{"a/file2.js"},
			expectedFiles: []string{"file1.js", "a/file1.txt", ".gitignore", "a/.gitignore"},
		},
		{
			name:      "Supports .dcignore rule file",
			repoPath:  t.TempDir(),
			ruleFiles: []string{".dcignore"},
			ruleFilesContent: map[string]string{
				".dcignore":   "/a/",
				"a/.dcignore": "!*.txt",
			},
			filesToFilter: []string{"a/file2.js"},
			expectedFiles: []string{"file1.js", "a/file1.txt", ".dcignore", "a/.dcignore"},
		},
		{
			name:      "Supports .snyk style exclude rules",
			repoPath:  t.TempDir(),
			ruleFiles: []string{".snyk"},
			ruleFilesContent: map[string]string{
				".snyk": `
exclude:
  code:
    - path/to/code/ignore1
    - path/to/code/ignore2:
        reason: testing map format
        expires: 3026-01-01T00:00:00Z
  global:
    - path/to/global/ignore1
    - path/to/global/ignore2:
        reason: testing expired rule
        expires: 1999-01-01T00:00:00Z
`,
			},
			filesToFilter: []string{
				"path/to/code/ignore1/ignoredFile.java",
				"path/to/code/ignore2/ignoredFile.java",
				"path/to/global/ignore1/ignoredFile.java",
				"path/to/global/ignore2/ignoredFile.java", // expired, should NOT be filtered
			},
			expectedFiles: []string{"path/to/code/notIgnored.java", "path/to/global/ignore2/ignoredFile.java", ".snyk"},
		},
	}
	return cases
}

func setupTestFileSystem(t *testing.T, testCase fileFilterTestCase) {
	t.Helper()

	// create rule files
	for ignoreFilePath, ignoreFileContent := range testCase.ruleFilesContent {
		ignoreFileAbsPath := filepath.Join(testCase.repoPath, ignoreFilePath)
		createFileInPath(t, ignoreFileAbsPath, []byte(ignoreFileContent))
	}

	// create filesystem
	allFiles := append(testCase.expectedFiles, testCase.filesToFilter...)
	for _, file := range allFiles {
		// skip any rule files as they've already been created above
		for _, ruleFile := range testCase.ruleFiles {
			if strings.Contains(file, ruleFile) {
				filePath := filepath.Join(testCase.repoPath, file)
				createFileInPath(t, filePath, []byte{})
			}
		}
	}
}

func createFileInPath(tb testing.TB, filePath string, content []byte) {
	tb.Helper()
	baseDir := filepath.Dir(filePath)
	err := os.MkdirAll(baseDir, 0755)
	assert.NoError(tb, err)
	err = os.WriteFile(filePath, content, 0777)
	assert.NoError(tb, err)
}

func TestParseIgnoreRuleToGlobs(t *testing.T) {
	testCases := []struct {
		name           string
		rule           string
		baseDir        string
		invalidRules   []string
		expectedGlobs  []string
		skipNonWindows bool
	}{
		{
			name:          "invalid rules are ignored",
			rule:          ".",
			baseDir:       "/tmp/test",
			invalidRules:  []string{"."},
			expectedGlobs: []string{},
		},
		{
			name:         "handles special characters",
			rule:         "*$",
			baseDir:      "/tmp/test",
			invalidRules: []string{},
			expectedGlobs: []string{
				"/tmp/test/**/*\\$",
				"/tmp/test/**/*\\$/**",
			},
		},
		{
			name:          "single slash has no effect",
			rule:          "/",
			baseDir:       "/tmp/test",
			invalidRules:  []string{},
			expectedGlobs: []string{},
		},
		{
			name:          "negated single slash has no effect",
			rule:          "!/",
			baseDir:       "/tmp/test",
			invalidRules:  []string{},
			expectedGlobs: []string{},
		},
		{
			name:         "slash with star ignores everything",
			rule:         "/*",
			baseDir:      "/tmp/test",
			invalidRules: []string{},
			expectedGlobs: []string{
				"/tmp/test/*/**",
				"/tmp/test/*",
			},
		},
		{
			name:         "root directory pattern",
			rule:         "/foo",
			baseDir:      "/tmp/test",
			invalidRules: []string{},
			expectedGlobs: []string{
				"/tmp/test/foo/**",
				"/tmp/test/foo",
			},
		},
		{
			name:         "root directory with trailing slash",
			rule:         "/foo/",
			baseDir:      "/tmp/test",
			invalidRules: []string{},
			expectedGlobs: []string{
				"/tmp/test/foo/**",
			},
		},
		{
			name:         "non-root directory pattern",
			rule:         "foo",
			baseDir:      "/tmp/test",
			invalidRules: []string{},
			expectedGlobs: []string{
				"/tmp/test/**/foo/**",
				"/tmp/test/**/foo",
			},
		},
		{
			name:         "non-root directory with trailing slash",
			rule:         "foo/",
			baseDir:      "/tmp/test",
			invalidRules: []string{},
			expectedGlobs: []string{
				"/tmp/test/**/foo/**",
			},
		},
		{
			// A rule with enough "../" climbs above baseDir once filepath.Join cleans it, so the
			// base is no longer a prefix and buildGlob takes the fallback path. The base content
			// is gone at that point, so the remaining glob wildcards must be preserved.
			name:         "rule climbing above base uses fallback",
			rule:         "../../../../../../foo",
			baseDir:      "/tmp/test",
			invalidRules: []string{},
			expectedGlobs: []string{
				"/foo/**",
				"/foo",
			},
		},
		{
			name:         "base path with metacharacters uses native separator",
			rule:         "node_modules",
			baseDir:      filepath.Join(os.TempDir(), "OneDrive - Foobar (Team1)", "project"),
			invalidRules: []string{},
			expectedGlobs: []string{
				path.Join(filepath.ToSlash(os.TempDir()), "OneDrive - Foobar \\(Team1\\)", "project") + "/**/node_modules/**",
				path.Join(filepath.ToSlash(os.TempDir()), "OneDrive - Foobar \\(Team1\\)", "project") + "/**/node_modules",
			},
		},
		{
			// UNC paths (\\server\share) are Windows-only. filepath.Join preserves the \\
			// prefix on Windows but treats \ as literal filename characters on Unix.
			name:           "UNC path with metacharacters",
			rule:           "node_modules",
			baseDir:        filepath.Join("\\\\server", "share", "OneDrive - Foobar (Team1)", "project"),
			invalidRules:   []string{},
			skipNonWindows: true,
			expectedGlobs: []string{
				"//server/" + path.Join("share", "OneDrive - Foobar \\(Team1\\)", "project", "**", "node_modules", "**"),
				"//server/" + path.Join("share", "OneDrive - Foobar \\(Team1\\)", "project", "**", "node_modules"),
			},
		},
		{
			name:         "Windows drive letter path",
			rule:         "node_modules",
			baseDir:      filepath.Join("C:", string(filepath.Separator), "Users", "someone", "project"),
			invalidRules: []string{},
			expectedGlobs: []string{
				path.Join(filepath.ToSlash(filepath.Join("C:", string(filepath.Separator), "Users", "someone", "project")), "**", "node_modules", "**"),
				path.Join(filepath.ToSlash(filepath.Join("C:", string(filepath.Separator), "Users", "someone", "project")), "**", "node_modules"),
			},
		},
		{
			name:         "Windows drive letter path with metacharacters",
			rule:         "node_modules",
			baseDir:      filepath.Join("C:", string(filepath.Separator), "Users", "someone", "OneDrive - Foobar (Team1)", "project"),
			invalidRules: []string{},
			expectedGlobs: []string{
				path.Join(filepath.ToSlash(filepath.Join("C:", string(filepath.Separator), "Users")), "someone", "OneDrive - Foobar \\(Team1\\)", "project", "**", "node_modules", "**"),
				path.Join(filepath.ToSlash(filepath.Join("C:", string(filepath.Separator), "Users")), "someone", "OneDrive - Foobar \\(Team1\\)", "project", "**", "node_modules"),
			},
		},
		{
			name:         "base path with trailing slash",
			rule:         "node_modules",
			baseDir:      filepath.Join(os.TempDir(), "test") + string(filepath.Separator),
			invalidRules: []string{},
			expectedGlobs: []string{
				path.Join(filepath.ToSlash(filepath.Join(os.TempDir(), "test")), "**", "node_modules", "**"),
				path.Join(filepath.ToSlash(filepath.Join(os.TempDir(), "test")), "**", "node_modules"),
			},
		},
		{
			// Root Local Device path (NT namespace, \??\C:\...). On Windows filepath.ToSlash turns it into
			// /??/C:/... before parseIgnoreRuleToGlobs sees it; "??" is an ordinary path
			// segment and the single leading slash is preserved, so the base survives intact.
			name:           "root local device path preserved",
			rule:           "node_modules",
			baseDir:        filepath.Join("\\??", "C:", string(filepath.Separator), "Users", "someone", "project"),
			invalidRules:   []string{},
			skipNonWindows: true,
			expectedGlobs: []string{
				"/??/C:/Users/someone/project/**/node_modules/**",
				"/??/C:/Users/someone/project/**/node_modules",
			},
		},
		{
			// Extended-length path (\\?\C:\...). Windows-only because filepath.Join keeps the
			// backslash prefix on Windows but treats \ as literal filename characters on Unix.
			// On Windows filepath.ToSlash turns it into //?/C:/...; joinGlob preserves the
			// leading "//" that path.Clean would otherwise collapse to "/".
			name:           "extended-length path preserved",
			rule:           "node_modules",
			baseDir:        filepath.Join("\\\\?", "C:", string(filepath.Separator), "Users", "someone", "project"),
			invalidRules:   []string{},
			skipNonWindows: true,
			expectedGlobs: []string{
				"//?/C:/Users/someone/project/**/node_modules/**",
				"//?/C:/Users/someone/project/**/node_modules",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.skipNonWindows && runtime.GOOS != "windows" {
				t.Skip("UNC paths only exist on Windows")
			}
			globs := parseIgnoreRuleToGlobs(tc.rule, tc.baseDir, tc.invalidRules, true)
			assert.ElementsMatch(t, tc.expectedGlobs, globs,
				"Test Name: %s, Rule: %q, Expected: %v, Got: %v", tc.name, tc.rule, tc.expectedGlobs, globs)
		})
	}
}

// TestParseIgnoreRuleToGlobs_legacyBehavior locks in the pre-fix (enableMetacharacterFix=false)
// behavior byte-for-byte. To be removed in future releases.
func TestParseIgnoreRuleToGlobs_legacyBehavior(t *testing.T) {
	testCases := []struct {
		name          string
		rule          string
		baseDir       string
		expectedGlobs []string
	}{
		{
			// Only "$" is escaped in the legacy path; other regex metacharacters are left as-is
			// and can be misinterpreted by the regex-based matcher.
			name:    "only dollar sign is escaped",
			rule:    "*$",
			baseDir: "/tmp/test",
			expectedGlobs: []string{
				"/tmp/test/**/*\\$",
				"/tmp/test/**/*\\$/**",
			},
		},
		{
			// Parentheses are regex metacharacters that the legacy path does not escape, so a
			// path/rule containing them can silently fail to match as expected.
			name:    "parentheses are not escaped",
			rule:    "node_modules",
			baseDir: "/tmp/OneDrive - Foobar (Team1)/project",
			expectedGlobs: []string{
				"/tmp/OneDrive - Foobar (Team1)/project/**/node_modules/**",
				"/tmp/OneDrive - Foobar (Team1)/project/**/node_modules",
			},
		},
		{
			name:    "root directory pattern",
			rule:    "/foo",
			baseDir: "/tmp/test",
			expectedGlobs: []string{
				"/tmp/test/foo/**",
				"/tmp/test/foo",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			globs := parseIgnoreRuleToGlobs(tc.rule, tc.baseDir, []string{}, false)
			assert.ElementsMatch(t, tc.expectedGlobs, globs,
				"Test Name: %s, Rule: %q, Expected: %v, Got: %v", tc.name, tc.rule, tc.expectedGlobs, globs)
		})
	}
}

// CLI-1648: .gitignore filtering on paths with regex metacharacters follows the metacharacter-fix feature flag.
func TestFileFilter_MetacharacterFixToggle(t *testing.T) {
	setup := func(t *testing.T) (base, nodeModulesFile, appFile string) {
		t.Helper()
		base = filepath.Join(t.TempDir(), "OneDrive - Foobar (Team1)", "repo")
		nodeModulesFile = filepath.Join(base, "node_modules", "lib", "index.js")
		appFile = filepath.Join(base, "app.js")
		createFileInPath(t, nodeModulesFile, []byte("x"))
		createFileInPath(t, appFile, []byte("x"))
		createFileInPath(t, filepath.Join(base, ".gitignore"), []byte("node_modules\n"))
		return base, nodeModulesFile, appFile
	}

	filterFiles := func(t *testing.T, fileFilter *FileFilter) []string {
		t.Helper()
		globs, err := fileFilter.GetRules([]string{".gitignore"})
		assert.NoError(t, err)

		var filtered []string
		for f := range fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), globs) {
			filtered = append(filtered, f)
		}
		return filtered
	}

	t.Run("flag off reproduces the legacy behavior", func(t *testing.T) {
		base, nodeModulesFile, appFile := setup(t)
		config := newTestConfig(map[string]bool{FF_FILE_FILTER_METACHARACTER_FIX: false})
		fileFilter := NewFileFilter(base, &log.Logger, WithConfig(config))

		filtered := filterFiles(t, fileFilter)
		assert.Contains(t, filtered, appFile, "app.js should be scanned")
		assert.Contains(t, filtered, nodeModulesFile,
			"legacy behavior: node_modules is NOT excluded when the base path has metacharacters")
	})

	t.Run("flag unset behaves like the flag being off", func(t *testing.T) {
		base, nodeModulesFile, appFile := setup(t)
		fileFilter := NewFileFilter(base, &log.Logger, WithConfig(newTestConfig(nil)))

		filtered := filterFiles(t, fileFilter)
		assert.Contains(t, filtered, appFile, "app.js should be scanned")
		assert.Contains(t, filtered, nodeModulesFile, "legacy behavior reproduced")
	})

	t.Run("flag on excludes node_modules correctly", func(t *testing.T) {
		base, nodeModulesFile, appFile := setup(t)
		config := newTestConfig(map[string]bool{FF_FILE_FILTER_METACHARACTER_FIX: true})
		fileFilter := NewFileFilter(base, &log.Logger, WithConfig(config))

		filtered := filterFiles(t, fileFilter)
		assert.Contains(t, filtered, appFile, "app.js should be scanned")
		assert.NotContains(t, filtered, nodeModulesFile,
			"flag on: node_modules must be excluded even though the base path has metacharacters")
	})

	t.Run("no config keeps the fix disabled", func(t *testing.T) {
		base, nodeModulesFile, appFile := setup(t)
		fileFilter := NewFileFilter(base, &log.Logger)

		filtered := filterFiles(t, fileFilter)
		assert.Contains(t, filtered, appFile, "app.js should be scanned")
		assert.Contains(t, filtered, nodeModulesFile,
			"without a config the fix defaults to disabled, reproducing the legacy behavior")
	})
}

func TestFileFilter_SlashPatternInGitIgnore(t *testing.T) {
	t.Run("gitignore with single slash has no effect", func(t *testing.T) {
		tempDir := t.TempDir()

		// Create test files
		files := []string{
			"file1.txt",
			"file2.txt",
			"subdir/file3.txt",
			"subdir/nested/file4.txt",
		}

		for _, file := range files {
			filePath := filepath.Join(tempDir, file)
			createFileInPath(t, filePath, []byte("test content"))
		}

		// Create .gitignore with "/"
		gitignorePath := filepath.Join(tempDir, ".gitignore")
		createFileInPath(t, gitignorePath, []byte("/"))

		// Test file filtering
		fileFilter := NewFileFilter(tempDir, &log.Logger)
		rules, err := fileFilter.GetRules([]string{".gitignore"})
		assert.NoError(t, err)

		// Should only have default rules since "/" has no effect
		assert.Equal(t, fileFilter.defaultRules, rules, "Rules should only contain default rules")

		// Get all files and filter them
		allFiles := fileFilter.GetAllFiles()
		filteredFiles := fileFilter.GetFilteredFiles(allFiles, rules)

		// Collect filtered files
		var filteredFilesList []string
		for file := range filteredFiles {
			relPath, err := filepath.Rel(tempDir, file)
			assert.NoError(t, err)
			// Normalize path separators for cross-platform compatibility
			filteredFilesList = append(filteredFilesList, filepath.ToSlash(relPath))
		}

		// With "/" pattern, no files should be ignored (all files pass through)
		expectedFiles := []string{".gitignore", "file1.txt", "file2.txt", "subdir/file3.txt", "subdir/nested/file4.txt"}
		assert.ElementsMatch(t, expectedFiles, filteredFilesList, "All files should pass through filter")
	})

	t.Run("gitignore with /* ignores all files", func(t *testing.T) {
		tempDir := t.TempDir()

		// Create test files
		files := []string{
			"file1.txt",
			"file2.txt",
			"subdir/file3.txt",
		}

		for _, file := range files {
			filePath := filepath.Join(tempDir, file)
			createFileInPath(t, filePath, []byte("test content"))
		}

		// Create .gitignore with "/*"
		gitignorePath := filepath.Join(tempDir, ".gitignore")
		createFileInPath(t, gitignorePath, []byte("/*"))

		// Test file filtering
		fileFilter := NewFileFilter(tempDir, &log.Logger)
		rules, err := fileFilter.GetRules([]string{".gitignore"})
		assert.NoError(t, err)

		// Get all files and filter them
		allFiles := fileFilter.GetAllFiles()
		filteredFiles := fileFilter.GetFilteredFiles(allFiles, rules)

		// Collect filtered files
		var filteredFilesList []string
		for file := range filteredFiles {
			filteredFilesList = append(filteredFilesList, file)
		}

		// With "/*" pattern, all files should be ignored
		assert.Empty(t, filteredFilesList, "All files should be filtered out with /* pattern")
	})
}

func TestDotSnykExclude_isExpired(t *testing.T) {
	expiryTests := []struct {
		name        string
		expires     string
		expected    bool
		expectError bool
	}{
		{
			name:        "ISO 8601",
			expires:     "2000-01-01T00:00:00Z",
			expected:    true,
			expectError: false,
		},
		{
			name:        "Javascript ISO format (YYYY-MM-DDThh:mm:ss.fffZ)",
			expires:     "2000-12-31T00:00:00.000Z",
			expected:    true,
			expectError: false,
		},
		{
			name:        "Date only format (YYYY-MM-DD)",
			expires:     "2000-12-31",
			expected:    true,
			expectError: false,
		},
		{
			name:        "RFC 2822",
			expires:     "Mon, 01 Jan 3000 00:00:00 +0000",
			expected:    false,
			expectError: false,
		},
		{
			name:        "invalid timestamp",
			expires:     "invalid timestamp",
			expected:    false,
			expectError: true,
		},
		{
			name:        "no expiry",
			expires:     "",
			expected:    false,
			expectError: false,
		},
	}
	for _, test := range expiryTests {
		t.Run(test.name, func(t *testing.T) {
			exclude := newDotSnykExclude("test/path", test.expires)
			isExpired, err := exclude.IsExpired()
			if test.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, test.expected, isExpired)
		})
	}
}

type gitTrackedFilesTestCase struct {
	files        map[string]string
	trackedFiles []string
	ruleFiles    map[string]string
	noGitRepo    bool
}

func TestFileFilter_GitTrackedFilesNotFiltered(t *testing.T) {
	testCase := gitTrackedFilesTestCase{
		files: map[string]string{
			"tracked.log":   "tracked but ignored",
			"untracked.log": "untracked and ignored",
			"regular.txt":   "regular file",
		},
		trackedFiles: []string{"tracked.log", "regular.txt"},
		ruleFiles: map[string]string{
			".gitignore": "*.log\n",
		},
	}

	t.Run("committed files are not filtered even if they match gitignore", func(t *testing.T) {
		root, worktree := setupGitTrackedFilesTestCase(t, testCase)
		_, err := worktree.Commit("initial commit", &git.CommitOptions{
			Author: &object.Signature{
				Name:  "Test",
				Email: "test@test.com",
				When:  time.Now(),
			},
		})
		require.NoError(t, err)

		assertGitTrackedFiles(t, root, []string{".gitignore"}, false, []string{
			".gitignore",
			"regular.txt",
		})
		assertGitTrackedFiles(t, root, []string{".gitignore"}, true, []string{
			".gitignore",
			"regular.txt",
			"tracked.log",
		})
	})

	t.Run("staged but uncommitted files are not filtered even if they match gitignore", func(t *testing.T) {
		root, _ := setupGitTrackedFilesTestCase(t, testCase)

		assertGitTrackedFiles(t, root, []string{".gitignore"}, false, []string{
			".gitignore",
			"regular.txt",
		})
		assertGitTrackedFiles(t, root, []string{".gitignore"}, true, []string{
			".gitignore",
			"regular.txt",
			"tracked.log",
		})
	})

	t.Run("nested gitignore preserves matching tracked files", func(t *testing.T) {
		nestedTestCase := gitTrackedFilesTestCase{
			files: map[string]string{
				"src/tracked.generated.js":   "tracked",
				"src/untracked.generated.js": "untracked",
				"src/regular.js":             "regular",
			},
			trackedFiles: []string{"src/tracked.generated.js"},
			ruleFiles: map[string]string{
				"src/.gitignore": "*.generated.js\n",
			},
		}
		root, _ := setupGitTrackedFilesTestCase(t, nestedTestCase)

		assertGitTrackedFiles(t, root, []string{".gitignore"}, false, []string{
			"src/.gitignore",
			"src/regular.js",
		})
		assertGitTrackedFiles(t, root, []string{".gitignore"}, true, []string{
			"src/.gitignore",
			"src/regular.js",
			"src/tracked.generated.js",
		})
	})

	t.Run("dcignore still excludes tracked files matching gitignore", func(t *testing.T) {
		dcignoreTestCase := gitTrackedFilesTestCase{
			files: map[string]string{
				"vendored.log": "vendored",
				"regular.txt":  "regular",
			},
			trackedFiles: []string{"vendored.log"},
			ruleFiles: map[string]string{
				".gitignore": "vendored.log\n",
				".dcignore":  "vendored.log\n",
			},
		}
		root, _ := setupGitTrackedFilesTestCase(t, dcignoreTestCase)

		assertGitTrackedFiles(t, root, []string{".gitignore", ".dcignore"}, true, []string{
			".dcignore",
			".gitignore",
			"regular.txt",
		})
	})

	t.Run("snyk exclusion still excludes tracked files matching gitignore", func(t *testing.T) {
		snykTestCase := gitTrackedFilesTestCase{
			files: map[string]string{
				"secret.log":  "secret",
				"regular.txt": "regular",
			},
			trackedFiles: []string{"secret.log"},
			ruleFiles: map[string]string{
				".gitignore": "secret.log\n",
				".snyk": "exclude:\n" +
					"  global:\n" +
					"    - secret.log\n",
			},
		}
		root, _ := setupGitTrackedFilesTestCase(t, snykTestCase)

		assertGitTrackedFiles(t, root, []string{".gitignore", ".snyk"}, true, []string{
			".gitignore",
			".snyk",
			"regular.txt",
		})
	})

	t.Run("tracked files in an ignored directory are preserved", func(t *testing.T) {
		directoryTestCase := gitTrackedFilesTestCase{
			files: map[string]string{
				"build/tracked.js":   "tracked",
				"build/untracked.js": "untracked",
				"regular.js":         "regular",
			},
			trackedFiles: []string{"build/tracked.js"},
			ruleFiles: map[string]string{
				".gitignore": "build/\n",
			},
		}
		root, _ := setupGitTrackedFilesTestCase(t, directoryTestCase)

		assertGitTrackedFiles(t, root, []string{".gitignore"}, false, []string{
			".gitignore",
			"regular.js",
		})
		assertGitTrackedFiles(t, root, []string{".gitignore"}, true, []string{
			".gitignore",
			"build/tracked.js",
			"regular.js",
		})
	})

	t.Run("gitignore negation remains effective", func(t *testing.T) {
		negationTestCase := gitTrackedFilesTestCase{
			files: map[string]string{
				"gen/drop.js": "drop",
				"gen/keep.js": "keep",
				"regular.js":  "regular",
			},
			ruleFiles: map[string]string{
				".gitignore": "gen/*.js\n!gen/keep.js\n",
			},
		}
		root, _ := setupGitTrackedFilesTestCase(t, negationTestCase)

		expected := []string{
			".gitignore",
			"gen/keep.js",
			"regular.js",
		}
		assertGitTrackedFiles(t, root, []string{".gitignore"}, false, expected)
		assertGitTrackedFiles(t, root, []string{".gitignore"}, true, expected)
	})

	t.Run("files removed from the index remain excluded", func(t *testing.T) {
		removedTestCase := gitTrackedFilesTestCase{
			files: map[string]string{
				"removed.log": "removed",
				"regular.txt": "regular",
			},
			trackedFiles: []string{"removed.log"},
			ruleFiles: map[string]string{
				".gitignore": "removed.log\n",
			},
		}
		root, _ := setupGitTrackedFilesTestCase(t, removedTestCase)
		repo, err := git.PlainOpen(root)
		require.NoError(t, err)
		gitIndex, err := repo.Storer.Index()
		require.NoError(t, err)
		_, err = gitIndex.Remove("removed.log")
		require.NoError(t, err)
		require.NoError(t, repo.Storer.SetIndex(gitIndex))

		assertGitTrackedFiles(t, root, []string{".gitignore"}, true, []string{
			".gitignore",
			"regular.txt",
		})
	})

	t.Run("tracked files missing from the worktree do not affect filtering", func(t *testing.T) {
		missingTestCase := gitTrackedFilesTestCase{
			files: map[string]string{
				"gone.log":    "gone",
				"regular.txt": "regular",
			},
			trackedFiles: []string{"gone.log"},
			ruleFiles: map[string]string{
				".gitignore": "gone.log\n",
			},
		}
		root, _ := setupGitTrackedFilesTestCase(t, missingTestCase)
		require.NoError(t, os.Remove(filepath.Join(root, "gone.log")))

		assertGitTrackedFiles(t, root, []string{".gitignore"}, true, []string{
			".gitignore",
			"regular.txt",
		})
	})

	t.Run("feature flag is a no-op when no matching file is tracked", func(t *testing.T) {
		noTrackedMatchTestCase := gitTrackedFilesTestCase{
			files: map[string]string{
				"ignored.log": "ignored",
				"regular.txt": "regular",
			},
			trackedFiles: []string{"regular.txt"},
			ruleFiles: map[string]string{
				".gitignore": "*.log\n",
			},
		}
		root, _ := setupGitTrackedFilesTestCase(t, noTrackedMatchTestCase)

		expected := []string{
			".gitignore",
			"regular.txt",
		}
		assertGitTrackedFiles(t, root, []string{".gitignore"}, false, expected)
		assertGitTrackedFiles(t, root, []string{".gitignore"}, true, expected)
	})

	t.Run("outside a git repository keeps legacy filtering", func(t *testing.T) {
		noGitTestCase := gitTrackedFilesTestCase{
			files: map[string]string{
				"ignored.log": "ignored",
				"regular.txt": "regular",
			},
			ruleFiles: map[string]string{
				".gitignore": "*.log\n",
			},
			noGitRepo: true,
		}
		root, _ := setupGitTrackedFilesTestCase(t, noGitTestCase)

		assertGitTrackedFiles(t, root, []string{".gitignore"}, true, []string{
			".gitignore",
			"regular.txt",
		})
	})

	t.Run("scanning a repository subdirectory resolves tracked files from the repository root", func(t *testing.T) {
		subdirectoryTestCase := gitTrackedFilesTestCase{
			files: map[string]string{
				"src/tracked.generated.js":   "tracked",
				"src/untracked.generated.js": "untracked",
				"src/regular.js":             "regular",
			},
			trackedFiles: []string{"src/tracked.generated.js"},
			ruleFiles: map[string]string{
				"src/.gitignore": "*.generated.js\n",
			},
		}
		root, _ := setupGitTrackedFilesTestCase(t, subdirectoryTestCase)
		scanRoot := filepath.Join(root, "src")

		assertGitTrackedFiles(t, scanRoot, []string{".gitignore"}, false, []string{
			".gitignore",
			"regular.js",
		})
		assertGitTrackedFiles(t, scanRoot, []string{".gitignore"}, true, []string{
			".gitignore",
			"regular.js",
			"tracked.generated.js",
		})
	})

	t.Run("scanning through a symlinked parent preserves tracked files", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation may require elevated privileges on Windows")
		}

		root, _ := setupGitTrackedFilesTestCase(t, testCase)
		symlinkedParent := filepath.Join(t.TempDir(), "repo-parent")
		err := os.Symlink(filepath.Dir(root), symlinkedParent)
		require.NoError(t, err)
		scanRoot := filepath.Join(symlinkedParent, filepath.Base(root))

		assertGitTrackedFiles(t, scanRoot, []string{".gitignore"}, true, []string{
			".gitignore",
			"regular.txt",
			"tracked.log",
		})
	})
}

func TestFileFilter_GetRulesIdentifiesGitignoreRules(t *testing.T) {
	testCase := gitTrackedFilesTestCase{
		ruleFiles: map[string]string{
			".gitignore": "*.log\n",
			".dcignore":  "*.tmp\n",
			".snyk": "exclude:\n" +
				"  global:\n" +
				"    - secret.txt\n",
		},
		noGitRepo: true,
	}
	root, _ := setupGitTrackedFilesTestCase(t, testCase)

	tests := []struct {
		name           string
		ruleFile       string
		featureEnabled bool
		expectPrefix   bool
	}{
		{
			name:           "enabled gitignore",
			ruleFile:       ".gitignore",
			featureEnabled: true,
			expectPrefix:   true,
		},
		{
			name:           "disabled gitignore",
			ruleFile:       ".gitignore",
			featureEnabled: false,
			expectPrefix:   false,
		},
		{
			name:           "dcignore",
			ruleFile:       ".dcignore",
			featureEnabled: true,
			expectPrefix:   false,
		},
		{
			name:           "snyk",
			ruleFile:       ".snyk",
			featureEnabled: true,
			expectPrefix:   false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := newTestConfig(map[string]bool{
				FF_FILE_FILTER_METACHARACTER_FIX:   true,
				FF_GITIGNORE_RESPECT_TRACKED_FILES: test.featureEnabled,
			})
			fileFilter := NewFileFilter(root, &log.Logger, WithConfig(config))
			rules, err := fileFilter.GetRules([]string{test.ruleFile})
			require.NoError(t, err)
			require.Greater(t, len(rules), len(fileFilter.defaultRules))

			for _, rule := range rules[len(fileFilter.defaultRules):] {
				assert.Equal(t, test.expectPrefix, strings.HasPrefix(rule, gitIgnoreGlobPrefix))
			}
		})
	}
}

func setupGitTrackedFilesTestCase(t *testing.T, testCase gitTrackedFilesTestCase) (string, *git.Worktree) {
	t.Helper()

	root := t.TempDir()
	for file, content := range testCase.files {
		createFileInPath(t, filepath.Join(root, file), []byte(content))
	}

	var worktree *git.Worktree
	if !testCase.noGitRepo {
		repo, err := git.PlainInit(root, false)
		require.NoError(t, err)
		worktree, err = repo.Worktree()
		require.NoError(t, err)
		for _, file := range testCase.trackedFiles {
			_, err = worktree.Add(file)
			require.NoError(t, err)
		}
	}

	for file, content := range testCase.ruleFiles {
		createFileInPath(t, filepath.Join(root, file), []byte(content))
	}
	return root, worktree
}

func assertGitTrackedFiles(t *testing.T, root string, ruleFiles []string, featureFlagEnabled bool, expected []string) {
	t.Helper()

	for _, metacharacterFixEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("metacharacter_fix=%t", metacharacterFixEnabled), func(t *testing.T) {
			config := newTestConfig(map[string]bool{
				FF_FILE_FILTER_METACHARACTER_FIX:   metacharacterFixEnabled,
				FF_GITIGNORE_RESPECT_TRACKED_FILES: featureFlagEnabled,
			})

			filteredFiles := runFileFilter(t, NewFileFilter(root, &log.Logger, WithConfig(config)), ruleFiles...)
			actual := make([]string, 0, len(filteredFiles))
			for _, file := range filteredFiles {
				relativePath, err := filepath.Rel(root, file)
				require.NoError(t, err)
				actual = append(actual, filepath.ToSlash(relativePath))
			}

			assert.ElementsMatch(t, expected, actual)
		})
	}
}

// runFileFilter applies ruleFiles with the given FileFilter and returns the files that survive filtering.
func runFileFilter(t *testing.T, fileFilter *FileFilter, ruleFiles ...string) []string {
	t.Helper()

	rules, err := fileFilter.GetRules(ruleFiles)
	require.NoError(t, err)

	return drainFilteredFiles(t, fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), rules))
}

func drainFilteredFiles(t *testing.T, filesCh <-chan string) []string {
	t.Helper()

	var filteredFiles []string
	for file := range filesCh {
		filteredFiles = append(filteredFiles, file)
	}

	return filteredFiles
}

// filterRunMetrics holds what a single FileFilter run recorded, keyed by metric name.
type filterRunMetrics struct {
	ints  map[string]int
	bools map[string]bool
}

// metricsByScope groups everything a recorder saw by run scope, asserting the
// "file-filter.<scopeID>.<metric>" shape of every key on the way. Scope IDs are allocated
// inside a run and never exposed, so tests discover them here rather than predicting them.
func metricsByScope(t *testing.T, recorder *metrics.RecorderFake) map[string]filterRunMetrics {
	t.Helper()

	runs := make(map[string]filterRunMetrics)
	runFor := func(key string) (filterRunMetrics, string) {
		parts := strings.Split(key, ".")
		require.Len(t, parts, 3, "metric key %q must be %s.<scopeID>.<metric>", key, metricFileFilterPrefix)
		require.Equal(t, metricFileFilterPrefix, parts[0])

		run, ok := runs[parts[1]]
		if !ok {
			run = filterRunMetrics{ints: map[string]int{}, bools: map[string]bool{}}
			runs[parts[1]] = run
		}
		return run, parts[2]
	}

	for key, value := range recorder.IntValues {
		run, metric := runFor(key)
		run.ints[metric] = value
	}
	for key, value := range recorder.BoolValues {
		run, metric := runFor(key)
		run.bools[metric] = value
	}

	return runs
}

// singleRun returns the metrics of the one run a recorder is expected to have seen that recorded
// the given metric. The metric picks the kind of run: metricFileFilterDurationMs is recorded by
// GetFilteredFiles, metricFileFilterRulesBuildDurationMs by GetRules.
func singleRun(t *testing.T, recorder *metrics.RecorderFake, metric string) filterRunMetrics {
	t.Helper()

	var matched []filterRunMetrics
	for _, run := range metricsByScope(t, recorder) {
		if _, ok := run.ints[metric]; ok {
			matched = append(matched, run)
		}
	}
	require.Len(t, matched, 1, "expected exactly one run recording %q", metric)

	return matched[0]
}

func TestFileFilter_Metrics(t *testing.T) {
	// newRepo creates a directory holding a .gitignore plus one file that survives filtering.
	newRepo := func(t *testing.T) string {
		t.Helper()
		root := t.TempDir()
		createFileInPath(t, filepath.Join(root, ".gitignore"), []byte("ignored.txt\n"))
		createFileInPath(t, filepath.Join(root, "ignored.txt"), []byte("x"))
		createFileInPath(t, filepath.Join(root, "file.txt"), []byte("x"))
		return root
	}

	// The two feature flags carry opposite values so that a mix-up between their metric keys cannot pass.
	for _, test := range []struct {
		name                string
		metacharacterFix    bool
		respectTrackedFiles bool
	}{
		{name: "metacharacter fix only", metacharacterFix: true},
		{name: "respect tracked files only", respectTrackedFiles: true},
	} {
		t.Run("records every metric under run-scoped keys, "+test.name, func(t *testing.T) {
			recorder := &metrics.RecorderFake{}
			config := newTestConfig(map[string]bool{
				FF_FILE_FILTER_METACHARACTER_FIX:   test.metacharacterFix,
				FF_GITIGNORE_RESPECT_TRACKED_FILES: test.respectTrackedFiles,
			})
			fileFilter := NewFileFilter(newRepo(t), &log.Logger, WithConfig(config), WithMetrics(recorder))

			runFileFilter(t, fileFilter, ".gitignore")

			run := singleRun(t, recorder, metricFileFilterDurationMs)
			assert.Equal(t, map[string]bool{
				metricFileFilterMetacharacterFix:    test.metacharacterFix,
				metricFileFilterRespectTrackedFiles: test.respectTrackedFiles,
			}, run.bools)
			// .gitignore and file.txt pass the filter, ignored.txt does not
			assert.Equal(t, 2, run.ints[metricFileFilterSurvivingFileCount])
			assert.Contains(t, run.ints, metricFileFilterDurationMs)
			// newRepo isn't a git repository, so no tracked file is ever exempted from a gitignore rule
			assert.Equal(t, 0, run.ints[metricFileFilterTrackedFilesKeptCount])
			assert.Len(t, run.ints, 3)

			// Building the rules reports its duration and the flags it built them with, under a scope of its own.
			rulesRun := singleRun(t, recorder, metricFileFilterRulesBuildDurationMs)
			assert.Equal(t, map[string]bool{
				metricFileFilterMetacharacterFix:    test.metacharacterFix,
				metricFileFilterRespectTrackedFiles: test.respectTrackedFiles,
			}, rulesRun.bools)
			assert.Len(t, rulesRun.ints, 1)
		})
	}

	// Neither several FileFilter instances nor repeated runs of one instance may overwrite each other's values.
	// The rules are built once and reused, so every run has to report on its own rather than relying on GetRules.
	t.Run("every run reports under its own scope", func(t *testing.T) {
		recorder := &metrics.RecorderFake{}
		config := newTestConfig(map[string]bool{FF_FILE_FILTER_METACHARACTER_FIX: true})
		fileFilter := NewFileFilter(newRepo(t), &log.Logger, WithConfig(config), WithMetrics(recorder))

		rules, err := fileFilter.GetRules([]string{".gitignore"})
		require.NoError(t, err)

		drainFilteredFiles(t, fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), rules))
		drainFilteredFiles(t, fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), rules))
		runFileFilter(t, NewFileFilter(newRepo(t), &log.Logger, WithConfig(config), WithMetrics(recorder)), ".gitignore")

		// two GetFilteredFiles runs of one FileFilter, one GetRules, and one full runFileFilter
		// (GetRules + GetFilteredFiles), each under its own scope
		runs := metricsByScope(t, recorder)
		assert.Len(t, runs, 5)

		filterRuns := 0
		for scopeID, run := range runs {
			if count, ok := run.ints[metricFileFilterSurvivingFileCount]; ok {
				filterRuns++
				assert.Equal(t, 2, count, "scope %s", scopeID)
				assert.True(t, run.bools[metricFileFilterMetacharacterFix], "scope %s", scopeID)
			}
		}
		assert.Equal(t, 3, filterRuns)
	})

	t.Run("without a recorder filtering is unaffected", func(t *testing.T) {
		root := newRepo(t)

		for _, fileFilter := range []*FileFilter{
			NewFileFilter(root, &log.Logger),
			NewFileFilter(root, &log.Logger, WithMetrics(nil)),
		} {
			assert.ElementsMatch(t, []string{
				filepath.Join(root, ".gitignore"),
				filepath.Join(root, "file.txt"),
			}, runFileFilter(t, fileFilter, ".gitignore"))
		}
	})

	t.Run("records bool metrics when no ignore files produce globs", func(t *testing.T) {
		recorder := &metrics.RecorderFake{}
		config := newTestConfig(map[string]bool{FF_FILE_FILTER_METACHARACTER_FIX: true})
		root := t.TempDir()
		createFileInPath(t, filepath.Join(root, "file.txt"), []byte("x"))
		fileFilter := NewFileFilter(root, &log.Logger, WithConfig(config), WithMetrics(recorder))

		drainFilteredFiles(t, fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), nil))

		assert.Equal(t, map[string]bool{
			metricFileFilterMetacharacterFix:    true,
			metricFileFilterRespectTrackedFiles: false,
		}, singleRun(t, recorder, metricFileFilterDurationMs).bools)
	})

	// One FileFilter may be started from several goroutines at once: no run may race on shared
	// state or land in the scope of another. Run under -race to cover the former.
	t.Run("concurrent filter runs use distinct metric scopes", func(t *testing.T) {
		const concurrentRuns = 4
		recorder := &metrics.RecorderFake{}
		fileFilter := NewFileFilter(newRepo(t), &log.Logger, WithMetrics(recorder))

		var wg sync.WaitGroup
		wg.Add(concurrentRuns)
		for range concurrentRuns {
			go func() {
				defer wg.Done()
				drainFilteredFiles(t, fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), []string{"**/.git/**"}))
			}()
		}
		wg.Wait()

		runs := metricsByScope(t, recorder)
		assert.Len(t, runs, concurrentRuns)
		for scopeID, run := range runs {
			assert.Contains(t, run.ints, metricFileFilterDurationMs, "scope %s", scopeID)
		}
	})
}

func TestFileFilter_Metrics_TrackedFilesKeptCount(t *testing.T) {
	tests := []struct {
		name           string
		testCase       gitTrackedFilesTestCase
		ruleFiles      []string
		featureEnabled bool
		expectedCount  int
	}{
		{
			// regular.txt is tracked but no gitignore rule matches it, so it is not a kept file
			name: "counts every tracked file a gitignore rule would have excluded",
			testCase: gitTrackedFilesTestCase{
				files: map[string]string{
					"tracked.log":      "tracked but ignored",
					"also-tracked.log": "tracked but ignored",
					"untracked.log":    "untracked and ignored",
					"regular.txt":      "regular file",
				},
				trackedFiles: []string{"tracked.log", "also-tracked.log", "regular.txt"},
				ruleFiles:    map[string]string{".gitignore": "*.log\n"},
			},
			ruleFiles:      []string{".gitignore"},
			featureEnabled: true,
			expectedCount:  2,
		},
		{
			// vendored.log is exempted from .gitignore, but the .dcignore rule still excludes it
			name: "does not count a tracked file another rule still excludes",
			testCase: gitTrackedFilesTestCase{
				files:        map[string]string{"vendored.log": "vendored", "regular.txt": "regular"},
				trackedFiles: []string{"vendored.log"},
				ruleFiles: map[string]string{
					".gitignore": "vendored.log\n",
					".dcignore":  "vendored.log\n",
				},
			},
			ruleFiles:      []string{".gitignore", ".dcignore"},
			featureEnabled: true,
			expectedCount:  0,
		},
		{
			name: "does not count tracked files while the feature is disabled",
			testCase: gitTrackedFilesTestCase{
				files:        map[string]string{"tracked.log": "tracked but ignored"},
				trackedFiles: []string{"tracked.log"},
				ruleFiles:    map[string]string{".gitignore": "*.log\n"},
			},
			ruleFiles:      []string{".gitignore"},
			featureEnabled: false,
			expectedCount:  0,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root, _ := setupGitTrackedFilesTestCase(t, test.testCase)
			recorder := &metrics.RecorderFake{}
			config := newTestConfig(map[string]bool{FF_GITIGNORE_RESPECT_TRACKED_FILES: test.featureEnabled})
			fileFilter := NewFileFilter(root, &log.Logger, WithConfig(config), WithMetrics(recorder))

			runFileFilter(t, fileFilter, test.ruleFiles...)

			run := singleRun(t, recorder, metricFileFilterDurationMs)
			assert.Equal(t, test.expectedCount, run.ints[metricFileFilterTrackedFilesKeptCount])
		})
	}
}
