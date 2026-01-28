package uploadrevision_test

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	uploadrevision2 "github.com/snyk/go-application-framework/internal/api/fileupload/uploadrevision"
)

var (
	orgID = uuid.MustParse("9102b78b-c28d-4392-a39f-08dd26fd9622")
	revID = uuid.MustParse("ff1bd2c6-7a5f-48fb-9a5b-52d711c8b47f")
)

func TestClient_CreateRevision(t *testing.T) {
	srv, c := setupTestServer(t)
	defer srv.Close()

	resp, err := c.CreateRevision(context.Background(), orgID)

	require.NoError(t, err)
	expectedID := uuid.MustParse("a7d975fb-2076-49b7-bc1f-31c395c3ce93")
	assert.Equal(t, expectedID, resp.Data.ID)
}

func TestClient_CreateRevision_EmptyOrgID(t *testing.T) {
	c := uploadrevision2.NewClient(uploadrevision2.Config{})

	resp, err := c.CreateRevision(context.Background(), uuid.Nil)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, uploadrevision2.ErrEmptyOrgID)
}

func TestClient_CreateRevision_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	c := uploadrevision2.NewClient(uploadrevision2.Config{
		BaseURL: srv.URL,
	})

	resp, err := c.CreateRevision(context.Background(), orgID)

	assert.Nil(t, resp)
	var httpErr *uploadrevision2.HTTPError
	assert.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusInternalServerError, httpErr.StatusCode)
	assert.Equal(t, "create upload revision", httpErr.Operation)
}

func TestClient_UploadFiles(t *testing.T) {
	srv, c := setupTestServer(t)
	defer srv.Close()

	mockFS := fstest.MapFS{
		"foo/bar": {Data: []byte("asdf")},
	}
	fd, err := mockFS.Open("foo/bar")
	require.NoError(t, err)

	err = c.UploadFiles(context.Background(),
		orgID,
		revID,
		[]uploadrevision2.UploadFile{
			{Path: "foo/bar", File: fd},
		})

	require.NoError(t, err)
}

func TestClient_UploadFiles_MultipleFiles(t *testing.T) {
	srv, c := setupTestServer(t)
	defer srv.Close()

	mockFS := fstest.MapFS{
		"file1.txt":  {Data: []byte("content1")},
		"file2.json": {Data: []byte("content2")},
	}

	file1, err := mockFS.Open("file1.txt")
	require.NoError(t, err)
	file2, err := mockFS.Open("file2.json")
	require.NoError(t, err)

	err = c.UploadFiles(context.Background(),
		orgID,
		revID,
		[]uploadrevision2.UploadFile{
			{Path: "file1.txt", File: file1},
			{Path: "file2.json", File: file2},
		})

	require.NoError(t, err)
}

func TestClient_UploadFiles_EmptyOrgID(t *testing.T) {
	c := uploadrevision2.NewClient(uploadrevision2.Config{})

	mockFS := fstest.MapFS{
		"test.txt": {Data: []byte("content")},
	}
	file, err := mockFS.Open("test.txt")
	require.NoError(t, err)

	err = c.UploadFiles(context.Background(),
		uuid.Nil, // empty orgID
		revID,
		[]uploadrevision2.UploadFile{
			{Path: "test.txt", File: file},
		})

	assert.Error(t, err)
	assert.ErrorIs(t, err, uploadrevision2.ErrEmptyOrgID)
}

func TestClient_UploadFiles_EmptyRevisionID(t *testing.T) {
	c := uploadrevision2.NewClient(uploadrevision2.Config{})

	mockFS := fstest.MapFS{
		"test.txt": {Data: []byte("content")},
	}
	file, err := mockFS.Open("test.txt")
	require.NoError(t, err)

	err = c.UploadFiles(context.Background(),
		orgID,
		uuid.Nil, // empty revisionID
		[]uploadrevision2.UploadFile{
			{Path: "test.txt", File: file},
		})

	assert.Error(t, err)
	assert.ErrorIs(t, err, uploadrevision2.ErrEmptyRevisionID)
}

func TestClient_UploadFiles_FileSizeLimit(t *testing.T) {
	c := uploadrevision2.NewClient(uploadrevision2.Config{})

	largeContent := make([]byte, c.GetLimits().FileSizeLimit+1)
	mockFS := fstest.MapFS{
		"large_file.txt": {Data: largeContent},
	}

	file, err := mockFS.Open("large_file.txt")
	require.NoError(t, err)

	err = c.UploadFiles(context.Background(),
		orgID,
		revID,
		[]uploadrevision2.UploadFile{
			{Path: "large_file.txt", File: file},
		})

	assert.Error(t, err)
	var fileSizeErr *uploadrevision2.FileSizeLimitError
	assert.ErrorAs(t, err, &fileSizeErr)
	assert.Equal(t, "large_file.txt", fileSizeErr.FilePath)
	assert.Equal(t, c.GetLimits().FileSizeLimit+1, fileSizeErr.FileSize)
	assert.Equal(t, c.GetLimits().FileSizeLimit, fileSizeErr.Limit)
}

func TestClient_UploadFiles_FileCountLimit(t *testing.T) {
	c := uploadrevision2.NewClient(uploadrevision2.Config{})

	files := make([]uploadrevision2.UploadFile, c.GetLimits().FileCountLimit+1)
	mockFS := fstest.MapFS{}

	for i := range c.GetLimits().FileCountLimit + 1 {
		filename := fmt.Sprintf("file%d.txt", i)
		mockFS[filename] = &fstest.MapFile{Data: []byte("content")}

		file, err := mockFS.Open(filename)
		require.NoError(t, err)

		files[i] = uploadrevision2.UploadFile{
			Path: filename,
			File: file,
		}
	}

	err := c.UploadFiles(context.Background(), orgID, revID, files)

	assert.Error(t, err)
	var fileCountErr *uploadrevision2.FileCountLimitError
	assert.ErrorAs(t, err, &fileCountErr)
	assert.Equal(t, c.GetLimits().FileCountLimit+1, fileCountErr.Count)
	assert.Equal(t, c.GetLimits().FileCountLimit, fileCountErr.Limit)
}

func TestClient_UploadFiles_FilePathLengthLimit(t *testing.T) {
	c := uploadrevision2.NewClient(uploadrevision2.Config{})

	// Create a file path that exceeds the limit
	longFilePath := strings.Repeat("a", c.GetLimits().FilePathLengthLimit+1)

	mockFS := fstest.MapFS{
		"short_file.txt": {Data: []byte("content")},
	}

	file, err := mockFS.Open("short_file.txt")
	require.NoError(t, err)

	err = c.UploadFiles(context.Background(),
		orgID,
		revID,
		[]uploadrevision2.UploadFile{
			{Path: longFilePath, File: file},
		})

	assert.Error(t, err)
	var filePathLengthErr *uploadrevision2.FilePathLengthLimitError
	assert.ErrorAs(t, err, &filePathLengthErr)
	assert.Equal(t, longFilePath, filePathLengthErr.FilePath)
	assert.Equal(t, c.GetLimits().FilePathLengthLimit+1, filePathLengthErr.Length)
	assert.Equal(t, c.GetLimits().FilePathLengthLimit, filePathLengthErr.Limit)
}

func TestClient_UploadFiles_FilePathLengthExactlyAtLimit(t *testing.T) {
	srv, c := setupTestServer(t)
	defer srv.Close()

	// Create a file name that is exactly at the limit
	filePathAtLimit := strings.Repeat("a", c.GetLimits().FilePathLengthLimit)

	mockFS := fstest.MapFS{
		"short_file.txt": {Data: []byte("content")},
	}

	file, err := mockFS.Open("short_file.txt")
	require.NoError(t, err)

	// This should not error since the file path is exactly at the limit
	err = c.UploadFiles(context.Background(),
		orgID,
		revID,
		[]uploadrevision2.UploadFile{
			{Path: filePathAtLimit, File: file},
		})

	assert.NoError(t, err)
}

func TestClient_UploadFiles_TotalPayloadSizeLimit(t *testing.T) {
	c := uploadrevision2.NewClient(uploadrevision2.Config{})

	// Create multiple files that individually are under the size limit,
	// but together exceed the total payload size limit
	mockFS := fstest.MapFS{}
	files := []uploadrevision2.UploadFile{}

	// Use files that are 30MB each (under the 50MB individual limit)
	// 8 files = 240MB > 200MB total limit
	fileSize := int64(30_000_000)
	numFiles := 8

	for i := range numFiles {
		filename := fmt.Sprintf("file%d.txt", i)
		mockFS[filename] = &fstest.MapFile{Data: make([]byte, fileSize)}

		file, err := mockFS.Open(filename)
		require.NoError(t, err)

		files = append(files, uploadrevision2.UploadFile{
			Path: filename,
			File: file,
		})
	}

	err := c.UploadFiles(context.Background(), orgID, revID, files)

	assert.Error(t, err)
	var totalSizeErr *uploadrevision2.TotalPayloadSizeLimitError
	assert.ErrorAs(t, err, &totalSizeErr)
	assert.Equal(t, fileSize*int64(numFiles), totalSizeErr.TotalSize)
	assert.Equal(t, c.GetLimits().TotalPayloadSizeLimit, totalSizeErr.Limit)
}

func TestClient_UploadFiles_TotalPayloadSizeExactlyAtLimit(t *testing.T) {
	srv, c := setupTestServer(t)
	defer srv.Close()

	// Test boundary: exactly 200MB (should succeed)
	mockFS := fstest.MapFS{}
	files := []uploadrevision2.UploadFile{}

	// Create files that sum exactly to 200MB
	// 4 files of 50MB each = 200MB exactly
	fileSize := int64(10_000_000)
	numFiles := 5

	for i := 0; i < numFiles; i++ {
		filename := fmt.Sprintf("file%d.txt", i)
		mockFS[filename] = &fstest.MapFile{Data: make([]byte, fileSize)}

		file, err := mockFS.Open(filename)
		require.NoError(t, err)

		files = append(files, uploadrevision2.UploadFile{
			Path: filename,
			File: file,
		})
	}

	err := c.UploadFiles(context.Background(), orgID, revID, files)

	// Should succeed - exactly at limit is allowed
	assert.NoError(t, err)
}

func TestClient_UploadFiles_IndividualFileSizeExactlyAtLimit(t *testing.T) {
	srv, c := setupTestServer(t)
	defer srv.Close()

	// Test boundary: individual file exactly 50MB (should succeed)
	mockFS := fstest.MapFS{
		"exact_limit.bin": {Data: make([]byte, c.GetLimits().FileSizeLimit)},
	}

	file, err := mockFS.Open("exact_limit.bin")
	require.NoError(t, err)

	err = c.UploadFiles(context.Background(), orgID, revID, []uploadrevision2.UploadFile{
		{Path: "exact_limit.bin", File: file},
	})

	// Should succeed - exactly at limit is allowed
	assert.NoError(t, err)
}

func TestClient_UploadFiles_SpecialFileError(t *testing.T) {
	c := uploadrevision2.NewClient(uploadrevision2.Config{})

	tests := []struct {
		name          string
		setupFS       func() (fstest.MapFS, string)
		setupRealFile func() string
	}{
		{
			name: "directory file",
			setupFS: func() (fstest.MapFS, string) {
				return fstest.MapFS{
					"test-directory": &fstest.MapFile{
						Mode: fs.ModeDir,
					},
				}, "test-directory"
			},
		},
	}

	// on non windows os test this case
	if runtime.GOOS != "windows" {
		tests = append(tests, struct {
			name          string
			setupFS       func() (fstest.MapFS, string)
			setupRealFile func() string
		}{
			name: "device file",
			setupRealFile: func() string {
				return "/dev/null"
			},
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var file fs.File
			var filePath string
			var err error

			if tt.setupFS != nil {
				mockFS, path := tt.setupFS()
				filePath = path
				file, err = mockFS.Open(path)
				require.NoError(t, err)
			} else if tt.setupRealFile != nil {
				filePath = tt.setupRealFile()

				realFile, openErr := os.Open(filePath)
				require.NoError(t, openErr)
				defer realFile.Close()
				file = realFile
			}

			err = c.UploadFiles(context.Background(),
				orgID,
				revID,
				[]uploadrevision2.UploadFile{
					{Path: filePath, File: file},
				})

			assert.Error(t, err)

			var sfe *uploadrevision2.SpecialFileError
			assert.ErrorAs(t, err, &sfe)
			assert.Equal(t, filePath, sfe.FilePath)
		})
	}
}

func TestClient_UploadFiles_Symlink(t *testing.T) {
	srv, c := setupTestServer(t)
	defer srv.Close()

	tmpDir := t.TempDir()
	tmpFile := path.Join(tmpDir, "temp-regular-file")

	err := os.WriteFile(tmpFile, []byte("foo bar"), 0o600)
	require.NoError(t, err)

	tmpSlnPth := path.Join(tmpDir, "temp-symlink")
	err = os.Symlink(tmpFile, tmpSlnPth)
	require.NoError(t, err)

	tmpSln, err := os.Open(tmpSlnPth)
	require.NoError(t, err)
	defer tmpSln.Close()

	err = c.UploadFiles(context.Background(),
		orgID,
		revID,
		[]uploadrevision2.UploadFile{
			{Path: tmpSlnPth, File: tmpSln},
		})

	assert.NoError(t, err)
}

func TestClient_UploadFiles_EmptyFileList(t *testing.T) {
	c := uploadrevision2.NewClient(uploadrevision2.Config{})

	err := c.UploadFiles(context.Background(), orgID, revID, []uploadrevision2.UploadFile{})

	assert.Error(t, err)
	assert.ErrorIs(t, err, uploadrevision2.ErrNoFilesProvided)
}

func TestClient_SealRevision(t *testing.T) {
	srv, c := setupTestServer(t)
	defer srv.Close()

	resp, err := c.SealRevision(context.Background(), orgID, revID)

	require.NoError(t, err)
	assert.Equal(t, revID, resp.Data.ID)
	assert.True(t, resp.Data.Attributes.Sealed)
}

func TestClient_SealRevision_EmptyOrgID(t *testing.T) {
	c := uploadrevision2.NewClient(uploadrevision2.Config{})

	resp, err := c.SealRevision(context.Background(),
		uuid.Nil, // empty orgID
		revID,
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, uploadrevision2.ErrEmptyOrgID)
	assert.Nil(t, resp)
}

func TestClient_SealRevision_EmptyRevisionID(t *testing.T) {
	c := uploadrevision2.NewClient(uploadrevision2.Config{})

	resp, err := c.SealRevision(context.Background(),
		orgID,
		uuid.Nil, // empty revisionID
	)

	assert.Error(t, err)
	assert.ErrorIs(t, err, uploadrevision2.ErrEmptyRevisionID)
	assert.Nil(t, resp)
}

func setupTestServer(t *testing.T) (*httptest.Server, *uploadrevision2.HTTPSealableClient) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "2024-10-15", r.URL.Query().Get("version"))

		switch {
		// Create revision
		case r.Method == http.MethodPost &&
			r.URL.Path == "/hidden/orgs/9102b78b-c28d-4392-a39f-08dd26fd9622/upload_revisions":

			assert.Equal(t, "application/vnd.api+json", r.Header.Get("Content-Type"))

			w.WriteHeader(http.StatusCreated)
			_, err := w.Write([]byte(`{
				"data": {
					"attributes": {
						"revision_type": "snapshot",
						"sealed": false
					},
					"id": "a7d975fb-2076-49b7-bc1f-31c395c3ce93",
					"type": "upload_revision"
				}
			}`))
			assert.NoError(t, err)

		// Upload files
		case r.Method == http.MethodPost &&
			r.URL.Path == "/hidden/orgs/9102b78b-c28d-4392-a39f-08dd26fd9622/upload_revisions/ff1bd2c6-7a5f-48fb-9a5b-52d711c8b47f/files":

			assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
			assert.Contains(t, r.Header.Get("Content-Type"), "multipart/form-data")

			contentType := r.Header.Get("Content-Type")
			_, params, err := mime.ParseMediaType(contentType)
			require.NoError(t, err)
			boundary := params["boundary"]
			require.NotEmpty(t, boundary, "multipart boundary should be present")

			gzipReader, err := gzip.NewReader(r.Body)
			require.NoError(t, err)
			reader := multipart.NewReader(gzipReader, boundary)

			for {
				_, err := reader.NextPart()
				if errors.Is(err, io.EOF) {
					break
				}
				require.NoError(t, err)
			}

			w.WriteHeader(http.StatusNoContent)

		// Seal revision
		case r.Method == http.MethodPatch &&
			r.URL.Path == "/hidden/orgs/9102b78b-c28d-4392-a39f-08dd26fd9622/upload_revisions/ff1bd2c6-7a5f-48fb-9a5b-52d711c8b47f":

			assert.Equal(t, "application/vnd.api+json", r.Header.Get("Content-Type"))

			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`{
				"data": {
					"attributes": {
						"revision_type": "snapshot",
						"sealed": true
					},
					"id": "ff1bd2c6-7a5f-48fb-9a5b-52d711c8b47f",
					"type": "upload_revision"
				}
			}`))
			assert.NoError(t, err)

		default:
			t.Errorf("Unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	client := uploadrevision2.NewClient(uploadrevision2.Config{
		BaseURL: srv.URL,
	})

	return srv, client
}
