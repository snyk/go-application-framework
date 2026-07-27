package fileupload_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	uploadrevision2 "github.com/snyk/go-application-framework/internal/api/fileupload/uploadrevision"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
)

type upperFile struct {
	fs.File
}

func (u upperFile) Read(p []byte) (int, error) {
	n, err := u.File.Read(p)
	copy(p, bytes.ToUpper(p[:n]))
	return n, err
}

// doubledFile reports twice the size of the underlying file, emulating a transcoder
// whose content is larger than the content on disk.
type doubledFile struct {
	fs.File
}

func (d doubledFile) Stat() (fs.FileInfo, error) {
	info, err := d.File.Stat()
	if err != nil {
		return nil, err
	}

	return doubledFileInfo{info}, nil
}

type doubledFileInfo struct {
	fs.FileInfo
}

func (d doubledFileInfo) Size() int64 {
	return d.FileInfo.Size() * 2
}

// noCloseFile emulates a transcoder wrapper that does not delegate Close.
type noCloseFile struct {
	fs.File
}

func (noCloseFile) Close() error {
	return nil
}

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
			fileupload.WithContentTranscoder(func(f fs.File) (fs.File, error) { return upperFile{f}, nil }),
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
		ctx, _, client, dir := setupOptionsTest(t, uploadrevision2.FakeClientConfig{
			Limits: uploadrevision2.Limits{
				FileCountLimit:        10,
				FileSizeLimit:         20,
				TotalPayloadSizeLimit: 10_000,
				FilePathLengthLimit:   50,
			},
		}, files, fileupload.WithContentTranscoder(func(f fs.File) (fs.File, error) { return doubledFile{f}, nil }))

		paths := make(chan string, 1)
		paths <- path.Join(dir.Name(), "my file.go")
		close(paths)

		res, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.ErrorIs(t, err, fileupload.ErrNoFilesProvided)

		var fileSizeErr *uploadrevision2.FileSizeLimitError
		require.Len(t, res.SkippedFiles, 1)
		ff := res.SkippedFiles[0]
		assert.Equal(t, "my file.go", ff.Path)
		assert.ErrorAs(t, ff.Reason, &fileSizeErr)
		assert.Equal(t, int64(24), fileSizeErr.FileSize)
		assert.Equal(t, int64(20), fileSizeErr.Limit)
	})

	t.Run("uploading a file from chan the transcoder fails on", func(t *testing.T) {
		transcodeErr := errors.New("cannot transcode")
		ctx, _, client, dir := setupOptionsTest(t, defaultLimits, files,
			fileupload.WithContentTranscoder(func(fs.File) (fs.File, error) { return nil, transcodeErr }),
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

	t.Run("uploading a file from chan with a transcoder not delegating close", func(t *testing.T) {
		var transcoded []fs.File
		ctx, _, client, dir := setupOptionsTest(t, defaultLimits, files,
			fileupload.WithContentTranscoder(func(f fs.File) (fs.File, error) {
				transcoded = append(transcoded, f)
				return noCloseFile{f}, nil
			}),
		)

		paths := make(chan string, 1)
		paths <- path.Join(dir.Name(), "my file.go")
		close(paths)

		_, err := client.CreateRevisionFromChan(ctx, paths, dir.Name())
		require.NoError(t, err)

		require.Len(t, transcoded, 1)
		assert.ErrorIs(t, transcoded[0].Close(), os.ErrClosed)
	})
}
