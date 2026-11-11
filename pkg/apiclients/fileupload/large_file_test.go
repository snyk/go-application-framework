package fileupload_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	uploadrevision2 "github.com/snyk/go-application-framework/internal/api/fileupload/uploadrevision"
	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload"
)

const (
	testChunkSize = 10
	// maxConcurrentChunks mirrors the client chunk upload concurrency.
	maxConcurrentChunks = 5
)

// recordingClient wraps the fake low-level client to observe and control uploads.
type recordingClient struct {
	*uploadrevision2.FakeSealableClient

	mu          sync.Mutex
	revisionID  uploadrevision2.RevisionID
	uploads     int
	inFlight    int
	maxInFlight int
	delay       time.Duration
	failOn      string
}

func (r *recordingClient) UploadFiles(ctx context.Context, orgID uploadrevision2.OrgID, revisionID uploadrevision2.RevisionID, files []uploadrevision2.UploadFile) error {
	r.mu.Lock()
	r.uploads++
	r.revisionID = revisionID
	r.inFlight++
	r.maxInFlight = max(r.maxInFlight, r.inFlight)
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		r.inFlight--
		r.mu.Unlock()
	}()

	if r.failOn != "" && files[0].Path == r.failOn {
		return errors.New("upload failed")
	}

	if r.delay > 0 {
		select {
		case <-time.After(r.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if err := ctx.Err(); err != nil {
		return err
	}

	return r.FakeSealableClient.UploadFiles(ctx, orgID, revisionID, files)
}

func setupLargeFileTest(t *testing.T, content []byte) (fileupload.Client, *recordingClient, string) {
	t.Helper()

	rec := &recordingClient{
		FakeSealableClient: uploadrevision2.NewFakeSealableClient(uploadrevision2.FakeClientConfig{
			Limits: uploadrevision2.Limits{
				FileCountLimit:        10,
				FileSizeLimit:         testChunkSize,
				TotalPayloadSizeLimit: testChunkSize,
				FilePathLengthLimit:   256,
			},
		}),
	}

	path := filepath.Join(t.TempDir(), "bundle")
	require.NoError(t, os.WriteFile(path, content, 0o600))

	client := fileupload.NewClient(nil, fileupload.Config{OrgID: uuid.New()}, fileupload.WithUploadRevisionSealableClient(rec), fileupload.WithLargeFileUpload(true))

	return client, rec, path
}

func testContent(size int) []byte {
	content := make([]byte, size)
	for i := range content {
		content[i] = byte('a' + i%26)
	}
	return content
}

func Test_CreateRevisionFromLargeFile_Chunks(t *testing.T) {
	tests := []struct {
		name           string
		size           int
		expectedChunks []string
	}{
		{"smaller than one chunk", 5, []string{"bundle_chunk_0000"}},
		{"exactly one chunk", testChunkSize, []string{"bundle_chunk_0000"}},
		{"one byte over a chunk", testChunkSize + 1, []string{"bundle_chunk_0000", "bundle_chunk_0001"}},
		{"exact multiple", 3 * testChunkSize, []string{"bundle_chunk_0000", "bundle_chunk_0001", "bundle_chunk_0002"}},
		{"one byte under a multiple", 3*testChunkSize - 1, []string{"bundle_chunk_0000", "bundle_chunk_0001", "bundle_chunk_0002"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			content := testContent(tc.size)
			client, rec, path := setupLargeFileTest(t, content)

			res, err := createFromLargeFile(t.Context(), client, path)
			require.NoError(t, err)

			files, err := rec.GetSealedRevisionFiles(res.RevisionID)
			require.NoError(t, err)

			sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

			var names []string
			var reassembled bytes.Buffer
			for i, f := range files {
				names = append(names, f.Path)
				reassembled.WriteString(f.Content)
				if i < len(files)-1 {
					assert.Len(t, f.Content, testChunkSize, "all chunks but the last have the same size")
				}
			}

			assert.Equal(t, tc.expectedChunks, names)
			assert.Equal(t, content, reassembled.Bytes())
		})
	}
}

func Test_CreateRevisionFromLargeFile_Validation(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		client, rec, path := setupLargeFileTest(t, []byte("x"))
		_, err := createFromLargeFile(t.Context(), client, path+"-missing")

		var accessErr *fileupload.FileAccessError
		require.ErrorAs(t, err, &accessErr)
		assert.Zero(t, rec.uploads)
	})

	t.Run("directory", func(t *testing.T) {
		client, _, _ := setupLargeFileTest(t, []byte("x"))
		_, err := createFromLargeFile(t.Context(), client, t.TempDir())

		var specialErr *fileupload.SpecialFileError
		require.ErrorAs(t, err, &specialErr)
	})

	t.Run("empty file", func(t *testing.T) {
		client, rec, path := setupLargeFileTest(t, []byte{})
		_, err := createFromLargeFile(t.Context(), client, path)

		require.ErrorIs(t, err, fileupload.ErrNoFilesProvided)
		assert.Zero(t, rec.uploads)
	})

	t.Run("file over 10 GB is rejected before upload", func(t *testing.T) {
		client, rec, path := setupLargeFileTest(t, []byte("x"))
		require.NoError(t, os.Truncate(path, 10_000_000_001)) // sparse
		_, err := createFromLargeFile(t.Context(), client, path)

		var sizeErr *fileupload.FileSizeLimitError
		require.ErrorAs(t, err, &sizeErr)
		assert.Zero(t, rec.uploads)
	})
}

func Test_CreateRevisionFromLargeFile_Concurrency(t *testing.T) {
	content := testContent(11 * testChunkSize)

	t.Run("upload max chunkConcurrency chunks in parallel", func(t *testing.T) {
		client, rec, path := setupLargeFileTest(t, content)
		rec.delay = 25 * time.Millisecond

		_, err := createFromLargeFile(t.Context(), client, path)
		require.NoError(t, err)
		assert.Equal(t, maxConcurrentChunks, rec.maxInFlight)
		assert.Greater(t, rec.maxInFlight, 1)
	})
}

func Test_CreateRevisionFromLargeFile_Errors(t *testing.T) {
	content := testContent(10 * testChunkSize)

	t.Run("first error cancels remaining chunks and revision is not sealed", func(t *testing.T) {
		client, rec, path := setupLargeFileTest(t, content)
		rec.failOn = "bundle_chunk_0001"
		rec.delay = 25 * time.Millisecond

		_, err := createFromLargeFile(t.Context(), client, path)
		require.ErrorContains(t, err, "bundle_chunk_0001")
		// the first chunkConcurrency chunks start together, the remaining 5 of 10 must never start
		assert.LessOrEqual(t, rec.uploads, 5)

		_, err = rec.GetSealedRevisionFiles(rec.revisionID)
		require.ErrorContains(t, err, "not sealed")
	})

	t.Run("canceled context stops the upload", func(t *testing.T) {
		client, rec, path := setupLargeFileTest(t, content)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		_, err := createFromLargeFile(ctx, client, path)
		require.ErrorIs(t, err, context.Canceled)
		assert.Zero(t, rec.uploads)
	})
}

// createFromLargeFile uploads the single file at path through the large file mode of the client.
func createFromLargeFile(ctx context.Context, client fileupload.Client, path string) (fileupload.UploadResult, error) {
	paths := make(chan string, 1)
	paths <- filepath.Base(path)
	close(paths)

	return client.CreateRevisionFromChan(ctx, paths, filepath.Dir(path))
}

func Test_CreateRevisionFromChan_LargeFile_MultipleFiles(t *testing.T) {
	client, rec, first := setupLargeFileTest(t, testContent(testChunkSize+1))
	dir := filepath.Dir(first)
	secondContent := testContent(2*testChunkSize + 3)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.txt"), secondContent, 0o600))

	paths := make(chan string, 2)
	paths <- "bundle"
	paths <- "other.txt"
	close(paths)

	res, err := client.CreateRevisionFromChan(t.Context(), paths, dir)
	require.NoError(t, err)
	assert.Equal(t, 2, res.UploadedFilesCount)
	assert.Empty(t, res.SkippedFiles)

	files, err := rec.GetSealedRevisionFiles(res.RevisionID)
	require.NoError(t, err)

	byName := map[string]string{}
	for _, f := range files {
		byName[f.Path] = f.Content
	}
	assert.Len(t, byName, 5)
	assert.Equal(t, string(secondContent[testChunkSize:2*testChunkSize]), byName["other.txt_chunk_0001"])
	assert.Contains(t, byName, "bundle_chunk_0001")
}

func Test_CreateRevisionFromChan_LargeFile_NoPaths(t *testing.T) {
	client, rec, path := setupLargeFileTest(t, testContent(1))

	paths := make(chan string)
	close(paths)

	_, err := client.CreateRevisionFromChan(t.Context(), paths, filepath.Dir(path))
	require.ErrorIs(t, err, fileupload.ErrNoFilesProvided)
	assert.Zero(t, rec.uploads)
}
