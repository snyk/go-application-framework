package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

		fileFilter := NewFileFilter(tempDir)
		actualFiles := fileFilter.GetAllFiles()
		expectedFiles := []string{tempFile1, tempFile2}

		var actualFilesChanLen int
		for actualFile := range actualFiles {
			actualFilesChanLen++
			assert.Contains(t, expectedFiles, actualFile)
		}
		assert.Equal(t, len(expectedFiles), actualFilesChanLen)
	})
}

func TestFileFilter_GetRules(t *testing.T) {
	// create temp filesystem
	tempDir := t.TempDir()
	tempFile1 := filepath.Join(tempDir, "test1.ts")
	createFileInPath(t, tempFile1, []byte{})
	tempFile2 := filepath.Join(tempDir, "test2.ts")
	createFileInPath(t, tempFile2, []byte{})

	t.Run("includes default rules", func(t *testing.T) {
		// create fileFilter
		fileFilter := NewFileFilter(tempDir)
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
		fileFilter := NewFileFilter(tempDir)
		actualRules, err := fileFilter.GetRules(ruleFiles)
		assert.NoError(t, err)

		// create expected rules
		expectedRules := append(
			[]string{
				fmt.Sprintf("%s/**/test1.ts/**", tempDir), // apply ignore in subDirs
				fmt.Sprintf("%s/**/test1.ts", tempDir),    // apply ignore in curDir
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

			fileFilter := NewFileFilter(testCase.repoPath)

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
	createFileInPath(b, ignoreFile, []byte("folder_1\n"))
	b.Log("Created ignore file")

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		fileFilter := NewFileFilter(rootDir)

		b.StartTimer()
		files := fileFilter.GetAllFiles()
		globs, err := fileFilter.GetRules(ruleFiles)
		assert.NoError(b, err)
		filteredFiles := fileFilter.GetFilteredFiles(files, globs)
		b.StopTimer()

		var actualFilteredFilesLen int
		for range filteredFiles {
			actualFilteredFilesLen++
		}

		assert.Equal(b, filesPerFolder*(folderDepth-1), actualFilteredFilesLen)
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
    - path/to/code/ignore2
  global:
    - path/to/global/ignore1
    - path/to/global/ignore2
`,
			},
			filesToFilter: []string{
				"path/to/code/ignore1/ignoredFile.java",
				"path/to/code/ignore2/ignoredFile.java",
				"path/to/global/ignore1/ignoredFile.java",
				"path/to/global/ignore2/ignoredFile.java",
			},
			expectedFiles: []string{"path/to/code/notIgnored.java", ".snyk"},
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
