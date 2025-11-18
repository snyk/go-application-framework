package fileupload_test

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload/filters"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload/uploadrevision"
)

var mainpath = filepath.Join("src", "main.go")
var utilspath = filepath.Join("src", "utils.go")
var helperpath = filepath.Join("src", "utils", "helper.go")
var docpath = filepath.Join("docs", "README.md")
var gomodpath = filepath.Join("src", "go.mod")
var scriptpath = filepath.Join("src", "script.js")
var packagelockpath = filepath.Join("src", "package.json")
var nonexistpath = filepath.Join("nonexistent", "file.go")
var missingpath = filepath.Join("another", "missing", "path.txt")

// CreateTmpFiles is an utility function used to create temporary files in tests.
func createTmpFiles(t *testing.T, files []uploadrevision.LoadedFile) (dir *os.File) {
	t.Helper()

	tempDir := t.TempDir()
	dir, err := os.Open(tempDir)
	if err != nil {
		panic(err)
	}

	for _, file := range files {
		fullPath := filepath.Join(tempDir, file.Path)

		parentDir := filepath.Dir(fullPath)
		if err := os.MkdirAll(parentDir, 0o755); err != nil {
			panic(err)
		}

		f, err := os.Create(fullPath)
		if err != nil {
			panic(err)
		}

		if _, err := f.WriteString(file.Content); err != nil {
			f.Close()
			panic(err)
		}
		f.Close()
	}

	t.Cleanup(func() {
		if dir != nil {
			dir.Close()
		}
	})

	return dir
}

func Test_CreateRevisionFromPaths(t *testing.T) {
	llcfg := uploadrevision.FakeClientConfig{
		Limits: uploadrevision.Limits{
			FileCountLimit:        10,
			FileSizeLimit:         100,
			TotalPayloadSizeLimit: 10_000,
			FilePathLengthLimit:   20,
		},
	}

	allowList := filters.AllowList{
		ConfigFiles: []string{"go.mod"},
		Extensions:  []string{".txt", ".go", ".md"},
	}

	t.Run("mixed files and directories", func(t *testing.T) {
		allFiles := []uploadrevision.LoadedFile{
			{Path: mainpath, Content: "package main"},
			{Path: utilspath, Content: "package utils"},
			{Path: "config.yaml", Content: "version: 1"},
			{Path: "README.md", Content: "# Project"},
		}

		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, allFiles, allowList, nil)

		paths := []string{
			filepath.Join(dir.Name(), "src"),       // Directory
			filepath.Join(dir.Name(), "README.md"), // Individual file
		}

		res, err := client.CreateRevisionFromPaths(ctx, paths)
		require.NoError(t, err)

		assert.Empty(t, res.FilteredFiles)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		require.Len(t, uploadedFiles, 3) // 2 from src/ + 1 README.md

		uploadedPaths := make([]string, len(uploadedFiles))
		for i, f := range uploadedFiles {
			uploadedPaths[i] = f.Path
		}
		assert.Contains(t, uploadedPaths, "main.go")
		assert.Contains(t, uploadedPaths, "utils.go")
		assert.Contains(t, uploadedPaths, "README.md")
	})

	t.Run("error handling with better context", func(t *testing.T) {
		ctx, _, client, _ := setupTest(t, llcfg, []uploadrevision.LoadedFile{}, allowList, nil)

		paths := []string{
			nonexistpath,
			missingpath,
		}

		_, err := client.CreateRevisionFromPaths(ctx, paths)
		require.Error(t, err)
		var fileAccessErr *uploadrevision.FileAccessError
		assert.ErrorAs(t, err, &fileAccessErr)
		assert.Equal(t, nonexistpath, fileAccessErr.FilePath)
	})
}

func Test_CreateRevisionFromDir(t *testing.T) {
	llcfg := uploadrevision.FakeClientConfig{
		Limits: uploadrevision.Limits{
			FileCountLimit:        2,
			FileSizeLimit:         100,
			TotalPayloadSizeLimit: 10_000,
			FilePathLengthLimit:   20,
		},
	}

	allowList := filters.AllowList{
		ConfigFiles: []string{"go.mod"},
		Extensions:  []string{".txt", ".go", ".md"},
	}

	t.Run("uploading a shallow directory", func(t *testing.T) {
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "file1.txt",
				Content: "content1",
			},
			{
				Path:    "file2.txt",
				Content: "content2",
			},
		}
		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, expectedFiles, allowList, nil)

		res, err := client.CreateRevisionFromDir(ctx, dir.Name())
		require.NoError(t, err)

		assert.Empty(t, res.FilteredFiles)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading a directory with nested files", func(t *testing.T) {
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    filepath.Join("src", "main.go"),
				Content: "package main\n\nfunc main() {}",
			},
			{
				Path:    filepath.Join("src", "utils", "helper.go"),
				Content: "package utils\n\nfunc Helper() {}",
			},
		}
		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, expectedFiles, allowList, nil)

		res, err := client.CreateRevisionFromDir(ctx, dir.Name())
		require.NoError(t, err)

		assert.Empty(t, res.FilteredFiles)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading a directory exceeding the file count limit for a single upload", func(t *testing.T) {
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "file1.txt",
				Content: "root level file",
			},
			{
				Path:    mainpath,
				Content: "package main\n\nfunc main() {}",
			},
			{
				Path:    helperpath,
				Content: "package utils\n\nfunc Helper() {}",
			},
			{
				Path:    docpath,
				Content: "# Project Documentation",
			},
			{
				Path:    gomodpath,
				Content: "foo bar",
			},
		}
		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, expectedFiles, allowList, nil)

		res, err := client.CreateRevisionFromDir(ctx, dir.Name())
		require.NoError(t, err)

		assert.Empty(t, res.FilteredFiles)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading a directory with file exceeding the file size limit", func(t *testing.T) {
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "file2.txt",
				Content: "foo",
			},
		}
		additionalFiles := []uploadrevision.LoadedFile{
			{
				Path:    "file1.txt",
				Content: "foo bar",
			},
		}

		allFiles := make([]uploadrevision.LoadedFile, 0, 2)
		allFiles = append(allFiles, expectedFiles...)
		allFiles = append(allFiles, additionalFiles...)
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision.FakeClientConfig{
			Limits: uploadrevision.Limits{
				FileCountLimit:        2,
				FileSizeLimit:         6,
				TotalPayloadSizeLimit: 100,
				FilePathLengthLimit:   20,
			},
		}, allFiles, allowList, nil)

		res, err := client.CreateRevisionFromDir(ctx, dir.Name())
		require.NoError(t, err)

		var fileSizeErr *uploadrevision.FileSizeLimitError
		assert.Len(t, res.FilteredFiles, 1)
		ff := res.FilteredFiles[0]
		assert.Contains(t, ff.Path, "file1.txt")
		assert.ErrorAs(t, ff.Reason, &fileSizeErr)
		assert.Equal(t, "file1.txt", fileSizeErr.FilePath)
		assert.Equal(t, int64(6), fileSizeErr.Limit)
		assert.Equal(t, int64(7), fileSizeErr.FileSize)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading a directory exceeding total payload size limit triggers batching", func(t *testing.T) {
		// Create files that together exceed the payload size limit but not the count limit
		// Each file is 30 bytes, limit is 70 bytes, so 3 files (90 bytes) should be split into 2 batches
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "file1.txt",
				Content: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", // 30 bytes
			},
			{
				Path:    "file2.txt",
				Content: "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", // 30 bytes
			},
			{
				Path:    "file3.txt",
				Content: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", // 30 bytes
			},
		}
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision.FakeClientConfig{
			Limits: uploadrevision.Limits{
				FileCountLimit:        10, // High enough to not trigger count-based batching
				FileSizeLimit:         50, // Each file is under this
				TotalPayloadSizeLimit: 70, // 70 bytes - forces batching by size
				FilePathLengthLimit:   20,
			},
		}, expectedFiles, allowList, nil)

		res, err := client.CreateRevisionFromDir(ctx, dir.Name())
		require.NoError(t, err)

		assert.Empty(t, res.FilteredFiles)
		// Success proves size-based batching works - without it, the low-level client
		// would reject the 90-byte payload (limit: 70 bytes).
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading large individual files near payload limit", func(t *testing.T) {
		// Tests edge case where individual files are large relative to the payload limit.
		// File1: 150 bytes, File2: 80 bytes, File3: 60 bytes; Limit: 200 bytes
		// Expected batches: [File1], [File2], [File3] - each file in its own batch
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "large1.txt",
				Content: string(make([]byte, 150)),
			},
			{
				Path:    "large2.txt",
				Content: string(make([]byte, 80)),
			},
			{
				Path:    "large3.txt",
				Content: string(make([]byte, 60)),
			},
		}
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision.FakeClientConfig{
			Limits: uploadrevision.Limits{
				FileCountLimit:        10,
				FileSizeLimit:         160,
				TotalPayloadSizeLimit: 200,
				FilePathLengthLimit:   20,
			},
		}, expectedFiles, allowList, nil)

		res, err := client.CreateRevisionFromDir(ctx, dir.Name())
		require.NoError(t, err)

		assert.Empty(t, res.FilteredFiles)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading files with variable sizes triggers optimal batching", func(t *testing.T) {
		// Tests realistic scenario with mixed file sizes.
		// Files: 10, 60, 5, 70, 45 bytes; Limit: 100 bytes
		// Expected batching: [10+60+5=75], [70], [45]
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "tiny.txt",
				Content: string(make([]byte, 10)),
			},
			{
				Path:    "medium.txt",
				Content: string(make([]byte, 60)),
			},
			{
				Path:    "small.txt",
				Content: string(make([]byte, 5)),
			},
			{
				Path:    "large.txt",
				Content: string(make([]byte, 70)),
			},
			{
				Path:    "mid.txt",
				Content: string(make([]byte, 45)),
			},
		}
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision.FakeClientConfig{
			Limits: uploadrevision.Limits{
				FileCountLimit:        10,
				FileSizeLimit:         80,
				TotalPayloadSizeLimit: 100,
				FilePathLengthLimit:   20,
			},
		}, expectedFiles, allowList, nil)

		res, err := client.CreateRevisionFromDir(ctx, dir.Name())
		require.NoError(t, err)

		assert.Empty(t, res.FilteredFiles)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading directory where both size and count limits would be reached", func(t *testing.T) {
		// Tests scenario where both limits are approached.
		// 8 files of 30 bytes each = 240 bytes total
		// FileCountLimit: 10, TotalPayloadSizeLimit: 200 bytes
		// Should batch by size first: [file1-6=180], [file7-8=60]
		expectedFiles := make([]uploadrevision.LoadedFile, 8)
		for i := 0; i < 8; i++ {
			expectedFiles[i] = uploadrevision.LoadedFile{
				Path:    fmt.Sprintf("file%d.txt", i),
				Content: string(make([]byte, 30)),
			}
		}
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision.FakeClientConfig{
			Limits: uploadrevision.Limits{
				FileCountLimit:        10,
				FileSizeLimit:         50,
				TotalPayloadSizeLimit: 200,
				FilePathLengthLimit:   20,
			},
		}, expectedFiles, allowList, nil)

		res, err := client.CreateRevisionFromDir(ctx, dir.Name())
		require.NoError(t, err)

		assert.Empty(t, res.FilteredFiles)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading a directory with filtering disabled", func(t *testing.T) {
		allFiles := []uploadrevision.LoadedFile{
			{
				Path:    mainpath,
				Content: "package main\n\nfunc main() {}",
			},
			{
				Path:    helperpath,
				Content: "package utils\n\nfunc Helper() {}",
			},
			{
				Path:    gomodpath,
				Content: "foo bar",
			},
			{
				Path:    scriptpath,
				Content: "console.log('hi')",
			},
			{
				Path:    packagelockpath,
				Content: "{}",
			},
		}

		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, allFiles, allowList, nil)

		res, err := client.CreateRevisionFromDir(ctx, dir.Name())
		require.NoError(t, err)

		assert.Empty(t, res.FilteredFiles)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, allFiles, uploadedFiles)
	})
}

func Test_CreateRevisionFromFile(t *testing.T) {
	llcfg := uploadrevision.FakeClientConfig{
		Limits: uploadrevision.Limits{
			FileCountLimit:        2,
			FileSizeLimit:         100,
			TotalPayloadSizeLimit: 10_000,
			FilePathLengthLimit:   20,
		},
	}

	allowList := filters.AllowList{
		ConfigFiles: []string{"go.mod"},
		Extensions:  []string{".txt", ".go", ".md"},
	}

	t.Run("uploading a file", func(t *testing.T) {
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "file1.txt",
				Content: "content1",
			},
		}
		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, expectedFiles, allowList, nil)

		res, err := client.CreateRevisionFromFile(ctx, path.Join(dir.Name(), "file1.txt"))
		require.NoError(t, err)

		assert.Empty(t, res.FilteredFiles)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading a file exceeding the file size limit", func(t *testing.T) {
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "file1.txt",
				Content: "foo bar",
			},
		}
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision.FakeClientConfig{
			Limits: uploadrevision.Limits{
				FileCountLimit:        1,
				FileSizeLimit:         6,
				TotalPayloadSizeLimit: 10_000,
				FilePathLengthLimit:   20,
			},
		}, expectedFiles, allowList, nil)

		res, err := client.CreateRevisionFromFile(ctx, path.Join(dir.Name(), "file1.txt"))
		require.NoError(t, err)

		var fileSizeErr *uploadrevision.FileSizeLimitError
		assert.Len(t, res.FilteredFiles, 1)
		ff := res.FilteredFiles[0]
		assert.Contains(t, ff.Path, "file1.txt")
		assert.ErrorAs(t, ff.Reason, &fileSizeErr)
		assert.Equal(t, "file1.txt", fileSizeErr.FilePath)
		assert.Equal(t, int64(6), fileSizeErr.Limit)
		assert.Equal(t, int64(7), fileSizeErr.FileSize)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, nil, uploadedFiles)
	})

	t.Run("uploading a file exceeding the file path limit", func(t *testing.T) {
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "file1.txt",
				Content: "foo bar",
			},
		}
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision.FakeClientConfig{
			Limits: uploadrevision.Limits{
				FileCountLimit:        1,
				FileSizeLimit:         10,
				TotalPayloadSizeLimit: 10_000,
				FilePathLengthLimit:   5,
			},
		}, expectedFiles, allowList, nil)

		res, err := client.CreateRevisionFromFile(ctx, path.Join(dir.Name(), "file1.txt"))
		require.NoError(t, err)

		var filePathErr *uploadrevision.FilePathLengthLimitError
		assert.Len(t, res.FilteredFiles, 1)
		ff := res.FilteredFiles[0]
		assert.Contains(t, ff.Path, "file1.txt")
		assert.ErrorAs(t, ff.Reason, &filePathErr)
		assert.Equal(t, "file1.txt", filePathErr.FilePath)
		assert.Equal(t, 5, filePathErr.Limit)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, nil, uploadedFiles)
	})

	t.Run("uploading a file with filtering disabled", func(t *testing.T) {
		expectedFiles := []uploadrevision.LoadedFile{
			{
				Path:    "script.js",
				Content: "console.log('hi')",
			},
		}

		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, expectedFiles, allowList, nil)

		res, err := client.CreateRevisionFromFile(ctx, path.Join(dir.Name(), "script.js"))
		require.NoError(t, err)

		assert.Empty(t, res.FilteredFiles)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})
}

func expectEqualFiles(t *testing.T, expectedFiles, uploadedFiles []uploadrevision.LoadedFile) {
	t.Helper()

	require.Equal(t, len(expectedFiles), len(uploadedFiles))

	slices.SortFunc(expectedFiles, func(fileA, fileB uploadrevision.LoadedFile) int {
		return strings.Compare(fileA.Path, fileB.Path)
	})

	slices.SortFunc(uploadedFiles, func(fileA, fileB uploadrevision.LoadedFile) int {
		return strings.Compare(fileA.Path, fileB.Path)
	})

	for i := range uploadedFiles {
		assert.Equal(t, expectedFiles[i].Path, uploadedFiles[i].Path)
		assert.Equal(t, expectedFiles[i].Content, uploadedFiles[i].Content)
	}
}

func setupTest(
	t *testing.T,
	llcfg uploadrevision.FakeClientConfig,
	files []uploadrevision.LoadedFile,
	allowList filters.AllowList,
	filtersErr error,
) (context.Context, *uploadrevision.FakeSealableClient, *fileupload.HTTPClient, *os.File) {
	t.Helper()

	ctx := context.Background()
	orgID := uuid.New()

	fakeSealeableClient := uploadrevision.NewFakeSealableClient(llcfg)
	fakeFiltersClient := filters.NewFakeClient(allowList, filtersErr)
	client := fileupload.NewClient(
		nil,
		fileupload.Config{
			OrgID: orgID,
		},
		fileupload.WithUploadRevisionSealableClient(fakeSealeableClient),
		fileupload.WithFiltersClient(fakeFiltersClient),
	)

	dir := createTmpFiles(t, files)

	return ctx, fakeSealeableClient, client, dir
}
