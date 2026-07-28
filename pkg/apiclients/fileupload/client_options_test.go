package fileupload_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	uploadrevision2 "github.com/snyk/go-application-framework/internal/api/fileupload/uploadrevision"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
)

func setupOptionsTest(
	t *testing.T,
	llcfg uploadrevision2.FakeClientConfig,
	files []uploadrevision2.LoadedFile,
	opts ...fileupload.Option,
) (context.Context, *uploadrevision2.FakeSealableClient, fileupload.Client, *os.File) {
	t.Helper()

	fakeSealableClient := uploadrevision2.NewFakeSealableClient(llcfg)
	client := fileupload.NewClient(
		nil,
		fileupload.Config{OrgID: uuid.New()},
		append([]fileupload.Option{fileupload.WithUploadRevisionSealableClient(fakeSealableClient)}, opts...)...,
	)

	return context.Background(), fakeSealableClient, client, createTmpFiles(t, files)
}

var defaultLimits = uploadrevision2.FakeClientConfig{
	Limits: uploadrevision2.Limits{
		FileCountLimit:        10,
		FileSizeLimit:         100,
		TotalPayloadSizeLimit: 10_000,
		FilePathLengthLimit:   50,
	},
}

func encodeSpaces(p string) string {
	return strings.ReplaceAll(p, " ", "%20")
}

func Test_CreateRevisionFromChan_Options(t *testing.T) {
	files := []uploadrevision2.LoadedFile{
		{Path: "my file.go", Content: "package main"},
	}

	t.Run("uploading a file from chan with an encoded path and transcoded content", func(t *testing.T) {
		ctx, fakeSealableClient, client, dir := setupOptionsTest(t, defaultLimits, files,
			fileupload.WithPathEncoder(encodeSpaces),
			fileupload.WithContentTranscoder(func(c []byte) ([]byte, error) { return bytes.ToUpper(c), nil }),
		)

		paths := make(chan string, 1)
		paths <- path.Join(dir.Name(), "my file.go")
		close(paths)

		res, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.NoError(t, err)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		require.Len(t, uploadedFiles, 1)
		assert.Equal(t, "my%20file.go", uploadedFiles[0].Path)
		assert.Equal(t, "PACKAGE MAIN", uploadedFiles[0].Content)
	})

	t.Run("uploading a file from chan whose encoded path exceeds the file path limit", func(t *testing.T) {
		ctx, _, client, dir := setupOptionsTest(t, uploadrevision2.FakeClientConfig{
			Limits: uploadrevision2.Limits{
				FileCountLimit:        10,
				FileSizeLimit:         100,
				TotalPayloadSizeLimit: 10_000,
				FilePathLengthLimit:   11,
			},
		}, files, fileupload.WithPathEncoder(encodeSpaces))

		paths := make(chan string, 1)
		paths <- path.Join(dir.Name(), "my file.go")
		close(paths)

		res, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.ErrorIs(t, err, fileupload.ErrNoFilesProvided)

		var filePathErr *uploadrevision2.FilePathLengthLimitError
		require.Len(t, res.SkippedFiles, 1)
		ff := res.SkippedFiles[0]
		assert.Equal(t, "my%20file.go", ff.Path)
		assert.ErrorAs(t, ff.Reason, &filePathErr)
		assert.Equal(t, "my%20file.go", filePathErr.FilePath)
		assert.Equal(t, 12, filePathErr.Length)
		assert.Equal(t, 11, filePathErr.Limit)
	})

	t.Run("uploading a file from chan whose transcoded content exceeds the file size limit", func(t *testing.T) {
		nestedFiles := []uploadrevision2.LoadedFile{
			{Path: filepath.Join("sub dir", "my file.go"), Content: "package main"},
		}
		ctx, _, client, dir := setupOptionsTest(t, uploadrevision2.FakeClientConfig{
			Limits: uploadrevision2.Limits{
				FileCountLimit:        10,
				FileSizeLimit:         20,
				TotalPayloadSizeLimit: 10_000,
				FilePathLengthLimit:   50,
			},
		}, nestedFiles,
			fileupload.WithPathEncoder(encodeSpaces),
			// Emulates a transcoder whose content is larger than the content on disk.
			fileupload.WithContentTranscoder(func(c []byte) ([]byte, error) {
				return append(bytes.Clone(c), c...), nil
			}),
		)

		paths := make(chan string, 1)
		paths <- path.Join(dir.Name(), "sub dir", "my file.go")
		close(paths)

		res, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.ErrorIs(t, err, fileupload.ErrNoFilesProvided)

		var fileSizeErr *uploadrevision2.FileSizeLimitError
		require.Len(t, res.SkippedFiles, 1)
		ff := res.SkippedFiles[0]
		assert.Equal(t, "sub%20dir/my%20file.go", ff.Path)
		assert.ErrorAs(t, ff.Reason, &fileSizeErr)
		assert.Equal(t, "sub%20dir/my%20file.go", fileSizeErr.FilePath)
		assert.Equal(t, int64(24), fileSizeErr.FileSize)
		assert.Equal(t, int64(20), fileSizeErr.Limit)
	})

	t.Run("uploading a file from chan the transcoder fails on", func(t *testing.T) {
		transcodeErr := errors.New("cannot transcode")
		ctx, _, client, dir := setupOptionsTest(t, defaultLimits, files,
			fileupload.WithContentTranscoder(func([]byte) ([]byte, error) { return nil, transcodeErr }),
		)

		paths := make(chan string, 1)
		paths <- path.Join(dir.Name(), "my file.go")
		close(paths)

		res, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.ErrorIs(t, err, fileupload.ErrNoFilesProvided)

		var fileAccessErr *uploadrevision2.FileAccessError
		require.Len(t, res.SkippedFiles, 1)
		ff := res.SkippedFiles[0]
		assert.Equal(t, "my file.go", ff.Path)
		require.ErrorAs(t, ff.Reason, &fileAccessErr)
		assert.ErrorIs(t, fileAccessErr.Err, transcodeErr)
	})

	t.Run("skips a path that is not a regular file", func(t *testing.T) {
		ctx, _, client, dir := setupOptionsTest(t, defaultLimits, files)

		require.NoError(t, os.Mkdir(path.Join(dir.Name(), "a dir"), 0o755))

		paths := make(chan string, 1)
		paths <- path.Join(dir.Name(), "a dir")
		close(paths)

		res, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.ErrorIs(t, err, fileupload.ErrNoFilesProvided)

		var specialFileErr *uploadrevision2.SpecialFileError
		require.Len(t, res.SkippedFiles, 1)
		require.ErrorAs(t, res.SkippedFiles[0].Reason, &specialFileErr)

		var fileAccessErr *uploadrevision2.FileAccessError
		assert.NotErrorAs(t, res.SkippedFiles[0].Reason, &fileAccessErr)
	})

	t.Run("uploads a symlink to a regular file", func(t *testing.T) {
		ctx, fakeSealableClient, client, dir := setupOptionsTest(t, defaultLimits, files)

		link := path.Join(dir.Name(), "link.go")
		require.NoError(t, os.Symlink(path.Join(dir.Name(), "my file.go"), link))

		paths := make(chan string, 1)
		paths <- link
		close(paths)

		res, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.NoError(t, err)

		uploadedFiles, err := fakeSealableClient.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		require.Len(t, uploadedFiles, 1)
		assert.Equal(t, "package main", uploadedFiles[0].Content)
	})
}
