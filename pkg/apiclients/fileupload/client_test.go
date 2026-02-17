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

	uploadrevision2 "github.com/snyk/go-application-framework/internal/api/fileupload/uploadrevision"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
)

var mainpath = filepath.Join("src", "main.go")
var utilspath = filepath.Join("src", "utils.go")
var helperpath = filepath.Join("src", "utils", "helper.go")
var docpath = filepath.Join("docs", "README.md")
var gomodpath = filepath.Join("src", "go.mod")
var nonexistpath = filepath.Join("nonexistent", "file.go")

// CreateTmpFiles is an utility function used to create temporary files in tests.
func createTmpFiles(t *testing.T, files []uploadrevision2.LoadedFile) (dir *os.File) {
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

func Test_CreateRevisionFromChan(t *testing.T) {
	llcfg := uploadrevision2.FakeClientConfig{
		Limits: uploadrevision2.Limits{
			FileCountLimit:        10,
			FileSizeLimit:         100,
			TotalPayloadSizeLimit: 10_000,
			FilePathLengthLimit:   20,
		},
	}

	t.Run("mixed files in paths chan", func(t *testing.T) {
		expectedFiles := []uploadrevision2.LoadedFile{
			{Path: mainpath, Content: "package main"},
			{Path: utilspath, Content: "package utils"},
			{Path: "config.yaml", Content: "version: 1"},
			{Path: "README.md", Content: "# Project"},
		}

		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, expectedFiles)

		paths := make(chan string)
		go func() {
			defer close(paths)
			for _, f := range expectedFiles {
				paths <- path.Join(dir.Name(), f.Path)
			}
		}()

		res, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.NoError(t, err)

		assert.Empty(t, res.SkippedFiles)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		require.Len(t, uploadedFiles, 4)

		uploadedPaths := make([]string, len(uploadedFiles))
		for i, f := range uploadedFiles {
			uploadedPaths[i] = f.Path
		}

		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("file access errors result in skipping the file", func(t *testing.T) {
		allFiles := []uploadrevision2.LoadedFile{
			{Path: "README.md", Content: "# Project"},
		}

		ctx, _, client, dir := setupTest(t, llcfg, allFiles)

		paths := make(chan string)
		go func() {
			defer close(paths)
			paths <- filepath.Join(dir.Name(), "README.md")
			paths <- nonexistpath
		}()

		res, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.NoError(t, err)

		assert.Equal(t, 1, res.UploadedFilesCount)
		assert.Len(t, res.SkippedFiles, 1)
		assert.Equal(t, nonexistpath, res.SkippedFiles[0].Path)
		assert.Contains(t, res.SkippedFiles[0].Reason.Error(), "cannot be accessed")
	})

	t.Run("uploading a file from chan exceeding the file size limit", func(t *testing.T) {
		expectedFiles := []uploadrevision2.LoadedFile{
			{
				Path:    "file1.txt",
				Content: "foo bar",
			},
		}
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision2.FakeClientConfig{
			Limits: uploadrevision2.Limits{
				FileCountLimit:        1,
				FileSizeLimit:         6,
				TotalPayloadSizeLimit: 10_000,
				FilePathLengthLimit:   20,
			},
		}, expectedFiles)

		paths := make(chan string)
		go func() {
			defer close(paths)
			paths <- path.Join(dir.Name(), "file1.txt")
		}()

		res, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.Error(t, err)

		var fileSizeErr *uploadrevision2.FileSizeLimitError
		assert.Len(t, res.SkippedFiles, 1)
		ff := res.SkippedFiles[0]
		assert.Contains(t, ff.Path, "file1.txt")
		assert.ErrorAs(t, ff.Reason, &fileSizeErr)
		assert.Equal(t, "file1.txt", fileSizeErr.FilePath)
		assert.Equal(t, int64(6), fileSizeErr.Limit)
		assert.Equal(t, int64(7), fileSizeErr.FileSize)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.Error(t, err)
		expectEqualFiles(t, nil, uploadedFiles)
	})

	t.Run("uploading a file from chan exceeding the file path limit", func(t *testing.T) {
		expectedFiles := []uploadrevision2.LoadedFile{
			{
				Path:    "file1.txt",
				Content: "foo bar",
			},
		}
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision2.FakeClientConfig{
			Limits: uploadrevision2.Limits{
				FileCountLimit:        1,
				FileSizeLimit:         10,
				TotalPayloadSizeLimit: 10_000,
				FilePathLengthLimit:   5,
			},
		}, expectedFiles)

		paths := make(chan string)
		go func() {
			defer close(paths)
			paths <- path.Join(dir.Name(), "file1.txt")
		}()

		res, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.Error(t, err)

		var filePathErr *uploadrevision2.FilePathLengthLimitError
		assert.Len(t, res.SkippedFiles, 1)
		ff := res.SkippedFiles[0]
		assert.Contains(t, ff.Path, "file1.txt")
		assert.ErrorAs(t, ff.Reason, &filePathErr)
		assert.Equal(t, "file1.txt", filePathErr.FilePath)
		assert.Equal(t, 5, filePathErr.Limit)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.Error(t, err)
		expectEqualFiles(t, nil, uploadedFiles)
	})

	t.Run("uploading a paths chan exceeding the file count limit for a single upload", func(t *testing.T) {
		expectedFiles := []uploadrevision2.LoadedFile{
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
		ctx, fakeSealableClient, client, dir := setupTest(t, llcfg, expectedFiles)

		paths := make(chan string)
		go func() {
			defer close(paths)
			for _, f := range expectedFiles {
				paths <- path.Join(dir.Name(), f.Path)
			}
		}()

		res, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.NoError(t, err)

		assert.Empty(t, res.SkippedFiles)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading files from chan with a file exceeding the file size limit", func(t *testing.T) {
		expectedFiles := []uploadrevision2.LoadedFile{
			{
				Path:    "file2.txt",
				Content: "foo",
			},
		}
		additionalFiles := []uploadrevision2.LoadedFile{
			{
				Path:    "file1.txt",
				Content: "foo bar",
			},
		}

		allFiles := make([]uploadrevision2.LoadedFile, 0, 2)
		allFiles = append(allFiles, expectedFiles...)
		allFiles = append(allFiles, additionalFiles...)
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision2.FakeClientConfig{
			Limits: uploadrevision2.Limits{
				FileCountLimit:        2,
				FileSizeLimit:         6,
				TotalPayloadSizeLimit: 100,
				FilePathLengthLimit:   20,
			},
		}, allFiles)

		paths := make(chan string)
		go func() {
			defer close(paths)
			for _, f := range allFiles {
				paths <- path.Join(dir.Name(), f.Path)
			}
		}()

		res, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.NoError(t, err)

		var fileSizeErr *uploadrevision2.FileSizeLimitError
		assert.Len(t, res.SkippedFiles, 1)
		ff := res.SkippedFiles[0]
		assert.Contains(t, ff.Path, "file1.txt")
		assert.ErrorAs(t, ff.Reason, &fileSizeErr)
		assert.Equal(t, "file1.txt", fileSizeErr.FilePath)
		assert.Equal(t, int64(6), fileSizeErr.Limit)
		assert.Equal(t, int64(7), fileSizeErr.FileSize)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading files from chan exceeding total payload size limit triggers batching", func(t *testing.T) {
		// Create files that together exceed the payload size limit but not the count limit
		// Each file is 30 bytes, limit is 70 bytes, so 3 files (90 bytes) should be split into 2 batches
		expectedFiles := []uploadrevision2.LoadedFile{
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
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision2.FakeClientConfig{
			Limits: uploadrevision2.Limits{
				FileCountLimit:        10, // High enough to not trigger count-based batching
				FileSizeLimit:         50, // Each file is under this
				TotalPayloadSizeLimit: 70, // 70 bytes - forces batching by size
				FilePathLengthLimit:   20,
			},
		}, expectedFiles)

		paths := make(chan string)
		go func() {
			defer close(paths)
			for _, f := range expectedFiles {
				paths <- path.Join(dir.Name(), f.Path)
			}
		}()

		res, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.NoError(t, err)

		assert.Empty(t, res.SkippedFiles)
		// Success proves size-based batching works - without it, the low-level client
		// would reject the 90-byte payload (limit: 70 bytes).
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading large individual files from chan near payload limit", func(t *testing.T) {
		// Tests edge case where individual files are large relative to the payload limit.
		// File1: 150 bytes, File2: 80 bytes, File3: 60 bytes; Limit: 200 bytes
		// Expected batches: [File1], [File2], [File3] - each file in its own batch
		expectedFiles := []uploadrevision2.LoadedFile{
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
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision2.FakeClientConfig{
			Limits: uploadrevision2.Limits{
				FileCountLimit:        10,
				FileSizeLimit:         160,
				TotalPayloadSizeLimit: 200,
				FilePathLengthLimit:   20,
			},
		}, expectedFiles)

		paths := make(chan string)
		go func() {
			defer close(paths)
			for _, f := range expectedFiles {
				paths <- path.Join(dir.Name(), f.Path)
			}
		}()

		res, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.NoError(t, err)

		assert.Empty(t, res.SkippedFiles)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading files from chan with variable sizes triggers optimal batching", func(t *testing.T) {
		// Tests realistic scenario with mixed file sizes.
		// Files: 10, 60, 5, 70, 45 bytes; Limit: 100 bytes
		// Expected batching: [10+60+5=75], [70], [45]
		expectedFiles := []uploadrevision2.LoadedFile{
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
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision2.FakeClientConfig{
			Limits: uploadrevision2.Limits{
				FileCountLimit:        10,
				FileSizeLimit:         80,
				TotalPayloadSizeLimit: 100,
				FilePathLengthLimit:   20,
			},
		}, expectedFiles)

		paths := make(chan string)
		go func() {
			defer close(paths)
			for _, f := range expectedFiles {
				paths <- path.Join(dir.Name(), f.Path)
			}
		}()

		res, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.NoError(t, err)

		assert.Empty(t, res.SkippedFiles)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})

	t.Run("uploading files from chan where both size and count limits would be reached", func(t *testing.T) {
		// Tests scenario where both limits are approached.
		// 8 files of 30 bytes each = 240 bytes total
		// FileCountLimit: 10, TotalPayloadSizeLimit: 200 bytes
		// Should batch by size first: [file1-6=180], [file7-8=60]
		expectedFiles := make([]uploadrevision2.LoadedFile, 8)
		for i := 0; i < 8; i++ {
			expectedFiles[i] = uploadrevision2.LoadedFile{
				Path:    fmt.Sprintf("file%d.txt", i),
				Content: string(make([]byte, 30)),
			}
		}
		ctx, fakeSealableClient, client, dir := setupTest(t, uploadrevision2.FakeClientConfig{
			Limits: uploadrevision2.Limits{
				FileCountLimit:        10,
				FileSizeLimit:         50,
				TotalPayloadSizeLimit: 200,
				FilePathLengthLimit:   20,
			},
		}, expectedFiles)

		paths := make(chan string)
		go func() {
			defer close(paths)
			for _, f := range expectedFiles {
				paths <- path.Join(dir.Name(), f.Path)
			}
		}()

		res, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.NoError(t, err)

		assert.Empty(t, res.SkippedFiles)
		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		expectEqualFiles(t, expectedFiles, uploadedFiles)
	})
}

func expectEqualFiles(t *testing.T, expectedFiles, uploadedFiles []uploadrevision2.LoadedFile) {
	t.Helper()

	require.Equal(t, len(expectedFiles), len(uploadedFiles))

	slices.SortFunc(expectedFiles, func(fileA, fileB uploadrevision2.LoadedFile) int {
		return strings.Compare(fileA.Path, fileB.Path)
	})

	slices.SortFunc(uploadedFiles, func(fileA, fileB uploadrevision2.LoadedFile) int {
		return strings.Compare(fileA.Path, fileB.Path)
	})

	for i := range uploadedFiles {
		assert.Equal(t, expectedFiles[i].Path, uploadedFiles[i].Path)
		assert.Equal(t, expectedFiles[i].Content, uploadedFiles[i].Content)
	}
}

func setupTest(
	t *testing.T,
	llcfg uploadrevision2.FakeClientConfig,
	files []uploadrevision2.LoadedFile,
) (context.Context, *uploadrevision2.FakeSealableClient, fileupload.Client, *os.File) {
	t.Helper()

	ctx := context.Background()
	orgID := uuid.New()

	fakeSealeableClient := uploadrevision2.NewFakeSealableClient(llcfg)
	client := fileupload.NewClient(
		nil,
		fileupload.Config{
			OrgID: orgID,
		},
		fileupload.WithUploadRevisionSealableClient(fakeSealeableClient),
	)

	dir := createTmpFiles(t, files)

	return ctx, fakeSealeableClient, client, dir
}
