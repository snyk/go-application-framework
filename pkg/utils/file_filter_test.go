package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
)

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
		"a.b",                       // dot in path (go-gitignore self-escapes; must not double-break)
		"a\\b",                      // literal backslash (legal on unix, illegal on windows)
	}

	// Characters that Windows does not allow in file/directory names, so such paths cannot
	// exist there and don't need to be exercised on that OS.
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

			fileFilter := NewFileFilter(base, &log.Logger)
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

// TestFileFilter_GetFilteredFiles_ignoreRuleScenarios covers ignore-rule behaviors that share
// the same shape: build a filesystem (including ignore files), filter it, then assert which
// files survive. "files" maps a slash-separated path (relative to the scan root) to its content;
// "excluded"/"kept" list slash-separated paths that must / must not be filtered out.
func TestFileFilter_GetFilteredFiles_ignoreRuleScenarios(t *testing.T) {
	scenarios := []struct {
		name      string
		files     map[string]string
		ruleFiles []string
		excluded  []string
		kept      []string
	}{
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
		{
			name: "parentheses in ignore rule pattern",
			files: map[string]string{
				".gitignore":         "foo(bar)\n",
				"foo(bar)/index.js":  "x",
				"foo(bar)x/index.js": "x",
				"app.js":             "x",
			},
			ruleFiles: []string{".gitignore"},
			// go-gitignore compiles (bar) as a regex group, not a literal directory name.
			excluded: []string{},
			kept:     []string{"foo(bar)/index.js", "foo(bar)x/index.js", "app.js"},
		},
		{
			name: "dollar sign in rule text matches directory name",
			files: map[string]string{
				".gitignore":          "price$tag\n",
				"price$tag/inside.js": "x",
				"price.js":            "x",
				"app.js":              "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"price$tag/inside.js"},
			kept:      []string{"price.js", "app.js"},
		},
		{
			name: "pipe in rule text is regex alternation not a literal character",
			files: map[string]string{
				".gitignore": "foo|bar\n",
				"foo.js":     "x",
				"bar.js":     "x",
				"baz.js":     "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"foo.js"},
			kept:      []string{"bar.js", "baz.js"},
		},
		{
			name: "dot in directory name still respects exclusion",
			files: map[string]string{
				".gitignore":          "node_modules\n",
				"v1.0/app.js":         "x",
				"node_modules/lib.js": "x",
			},
			ruleFiles: []string{".gitignore"},
			excluded:  []string{"node_modules/lib.js"},
			kept:      []string{"v1.0/app.js"},
		},
		{
			name: "snyk code exclude in repo directory with metacharacters",
			files: map[string]string{
				".snyk": `exclude:
  code:
    - node_modules
`,
				"pkg (core)/node_modules/lib.js": "x",
				"pkg (core)/src/app.js":          "x",
			},
			ruleFiles: []string{".snyk"},
			excluded:  []string{"pkg (core)/node_modules/lib.js"},
			kept:      []string{"pkg (core)/src/app.js"},
		},
		{
			name: "default git rule excludes dot-git contents",
			files: map[string]string{
				".git/config": "x",
				"src/app.js":  "x",
			},
			ruleFiles: []string{},
			excluded:  []string{".git/config"},
			kept:      []string{"src/app.js"},
		},
	}

	for _, tc := range scenarios {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for p, content := range tc.files {
				createFileInPath(t, filepath.Join(root, filepath.FromSlash(p)), []byte(content))
			}

			fileFilter := NewFileFilter(root, &log.Logger)
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

// TestFileFilter_GetFilteredFiles_dotSnykUnderMetacharParentPath ensures .snyk Code exclusions
// work when the scan root sits under a parent path with regex metacharacters (CLI-1648).
func TestFileFilter_GetFilteredFiles_dotSnykUnderMetacharParentPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("parent path shape uses characters awkward on Windows temp paths")
	}
	base := filepath.Join(t.TempDir(), "OneDrive - Foobar (Team1)", "repo")
	excluded := filepath.Join(base, "node_modules", "lib", "index.js")
	kept := filepath.Join(base, "src", "app.js")
	snykFile := filepath.Join(base, ".snyk")
	createFileInPath(t, excluded, []byte("x"))
	createFileInPath(t, kept, []byte("x"))
	createFileInPath(t, snykFile, []byte(`exclude:
  code:
    - node_modules
`))

	fileFilter := NewFileFilter(base, &log.Logger)
	globs, err := fileFilter.GetRules([]string{".snyk"})
	assert.NoError(t, err)

	var filtered []string
	for f := range fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), globs) {
		filtered = append(filtered, f)
	}

	assert.Contains(t, filtered, kept)
	assert.NotContains(t, filtered, excluded)
}

// TestFileFilter_GetFilteredFiles_dotGitExcludedUnderMetacharParentPath ensures the default
// **/.git/** rule still applies when the scan root is under a path with regex metacharacters.
func TestFileFilter_GetFilteredFiles_dotGitExcludedUnderMetacharParentPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("parent path shape uses characters awkward on Windows temp paths")
	}
	base := filepath.Join(t.TempDir(), "Program Files (x86)", "repo")
	gitConfig := filepath.Join(base, ".git", "config")
	appFile := filepath.Join(base, "src", "app.js")
	createFileInPath(t, gitConfig, []byte("x"))
	createFileInPath(t, appFile, []byte("x"))

	fileFilter := NewFileFilter(base, &log.Logger)
	globs, err := fileFilter.GetRules([]string{})
	assert.NoError(t, err)

	var filtered []string
	for f := range fileFilter.GetFilteredFiles(fileFilter.GetAllFiles(), globs) {
		filtered = append(filtered, f)
	}

	assert.Contains(t, filtered, appFile)
	assert.NotContains(t, filtered, gitConfig)
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
		name          string
		rule          string
		baseDir       string
		invalidRules  []string
		expectedGlobs []string
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
			name:         "parentheses in rule text",
			rule:         "foo(bar)",
			baseDir:      "/tmp/test",
			invalidRules: []string{},
			expectedGlobs: []string{
				"/tmp/test/**/foo(bar)/**",
				"/tmp/test/**/foo(bar)",
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			globs := parseIgnoreRuleToGlobs(tc.rule, tc.baseDir, tc.invalidRules)
			assert.ElementsMatch(t, tc.expectedGlobs, globs,
				"Rule: %q, Expected: %v, Got: %v", tc.rule, tc.expectedGlobs, globs)
		})
	}
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
