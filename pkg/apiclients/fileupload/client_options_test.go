package fileupload_test

import (
	"bytes"
	"context"
	"io/fs"
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

func Test_CreateRevisionFromChan_Options(t *testing.T) {
	llcfg := uploadrevision2.FakeClientConfig{
		Limits: uploadrevision2.Limits{
			FileCountLimit:        10,
			FileSizeLimit:         100,
			TotalPayloadSizeLimit: 10_000,
			FilePathLengthLimit:   50,
		},
	}

	files := []uploadrevision2.LoadedFile{
		{Path: "my file.go", Content: "package main"},
	}

	ctx := context.Background()
	fakeSealableClient := uploadrevision2.NewFakeSealableClient(llcfg)
	dir := createTmpFiles(t, files)

	client := fileupload.NewClient(
		nil,
		fileupload.Config{OrgID: uuid.New()},
		fileupload.WithUploadRevisionSealableClient(fakeSealableClient),
		fileupload.WithPathEncoder(func(p string) string { return strings.ReplaceAll(p, " ", "%20") }),
		fileupload.WithContentTranscoder(func(f fs.File) fs.File { return upperFile{f} }),
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
}
