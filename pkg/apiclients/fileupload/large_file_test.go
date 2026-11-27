package fileupload_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	// testChunkSize is the minimum chunk size accepted by the client.
	testChunkSize = 125_000
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
	// onUpload runs before the content of an upload is read.
	onUpload func()
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

	if r.onUpload != nil {
		r.onUpload()
	}

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
		{"empty file", 0, []string{"bundle_chunk_v1_0000"}},
		{"smaller than one chunk", 5, []string{"bundle_chunk_v1_0000"}},
		{"exactly one chunk", testChunkSize, []string{"bundle_chunk_v1_0000"}},
		{"one byte over a chunk", testChunkSize + 1, []string{"bundle_chunk_v1_0000", "bundle_chunk_v1_0001"}},
		{"exact multiple", 3 * testChunkSize, []string{"bundle_chunk_v1_0000", "bundle_chunk_v1_0001", "bundle_chunk_v1_0002"}},
		{"one byte under a multiple", 3*testChunkSize - 1, []string{"bundle_chunk_v1_0000", "bundle_chunk_v1_0001", "bundle_chunk_v1_0002"}},
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
			assert.Equal(t, string(content), reassembled.String())
		})
	}
}

func Test_CreateRevisionFromLargeFile_Validation(t *testing.T) {
	t.Run("missing file is skipped", func(t *testing.T) {
		client, rec, path := setupLargeFileTest(t, []byte("x"))
		res, err := createFromLargeFile(t.Context(), client, path+"-missing")

		require.ErrorIs(t, err, fileupload.ErrNoFilesProvided)
		require.Len(t, res.SkippedFiles, 1)
		assert.Equal(t, "bundle-missing", res.SkippedFiles[0].Path)
		var accessErr *fileupload.FileAccessError
		require.ErrorAs(t, res.SkippedFiles[0].Reason, &accessErr)
		assert.Equal(t, res.SkippedFiles[0].Path, accessErr.FilePath)
		assert.Zero(t, rec.uploads)
	})

	t.Run("skipped file is reported with the encoded path", func(t *testing.T) {
		_, rec, path := setupLargeFileTest(t, []byte("x"))
		client := fileupload.NewClient(nil, fileupload.Config{OrgID: uuid.New()},
			fileupload.WithUploadRevisionSealableClient(rec),
			fileupload.WithLargeFileUpload(true),
			fileupload.WithPathEncoder(func(p string) string { return strings.ReplaceAll(p, " ", "%20") }))

		res, err := createFromLargeFile(t.Context(), client, filepath.Join(filepath.Dir(path), "my file"))

		require.ErrorIs(t, err, fileupload.ErrNoFilesProvided)
		require.Len(t, res.SkippedFiles, 1)
		assert.Equal(t, "my%20file", res.SkippedFiles[0].Path)
		var accessErr *fileupload.FileAccessError
		require.ErrorAs(t, res.SkippedFiles[0].Reason, &accessErr)
		assert.Equal(t, "my%20file", accessErr.FilePath)
	})

	t.Run("directory is skipped", func(t *testing.T) {
		client, _, _ := setupLargeFileTest(t, []byte("x"))
		res, err := createFromLargeFile(t.Context(), client, t.TempDir())

		require.ErrorIs(t, err, fileupload.ErrNoFilesProvided)
		require.Len(t, res.SkippedFiles, 1)
		var specialErr *fileupload.SpecialFileError
		require.ErrorAs(t, res.SkippedFiles[0].Reason, &specialErr)
	})

	for name, targetExists := range map[string]bool{"symlink": true, "broken symlink": false} {
		t.Run(name+" is skipped without reading its target", func(t *testing.T) {
			client, rec, target := setupLargeFileTest(t, []byte("secret"))
			link := filepath.Join(filepath.Dir(target), "link")
			if !targetExists {
				target += "-missing"
			}
			symlinkOrSkip(t, target, link)

			res, err := createFromLargeFile(t.Context(), client, link)

			require.ErrorIs(t, err, fileupload.ErrNoFilesProvided)
			require.Len(t, res.SkippedFiles, 1)
			assert.Equal(t, "link", res.SkippedFiles[0].Path)
			var symlinkErr *fileupload.SymlinkError
			require.ErrorAs(t, res.SkippedFiles[0].Reason, &symlinkErr)
			assert.Equal(t, "link", symlinkErr.FilePath)
			assert.Zero(t, rec.uploads)
		})
	}

	t.Run("file whose chunk name is too long is skipped without aborting the revision", func(t *testing.T) {
		client, rec, first := setupLargeFileTest(t, testContent(testChunkSize+1))
		dir := filepath.Dir(first)
		longName := strings.Repeat("a", 250)
		require.NoError(t, os.WriteFile(filepath.Join(dir, longName), []byte("x"), 0o600))

		paths := make(chan string, 2)
		paths <- first
		paths <- filepath.Join(dir, longName)
		close(paths)

		res, err := client.CreateRevisionFromChan(t.Context(), paths, dir)
		require.NoError(t, err)
		assert.Equal(t, 1, res.UploadedFilesCount)
		require.Len(t, res.SkippedFiles, 1)
		assert.Equal(t, longName, res.SkippedFiles[0].Path)
		var limitErr *fileupload.FilePathLengthLimitError
		require.ErrorAs(t, res.SkippedFiles[0].Reason, &limitErr)

		files, err := rec.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		assert.Len(t, files, 2)
	})

	t.Run("skipped files do not abort the revision", func(t *testing.T) {
		client, rec, first := setupLargeFileTest(t, testContent(testChunkSize+1))
		dir := filepath.Dir(first)

		paths := make(chan string, 2)
		paths <- filepath.Join(dir, "missing.txt")
		paths <- first
		close(paths)

		res, err := client.CreateRevisionFromChan(t.Context(), paths, dir)
		require.NoError(t, err)
		assert.Equal(t, 1, res.UploadedFilesCount)
		require.Len(t, res.SkippedFiles, 1)
		assert.Equal(t, "missing.txt", res.SkippedFiles[0].Path)

		files, err := rec.GetSealedRevisionFiles(res.RevisionID)
		require.NoError(t, err)
		assert.Len(t, files, 2)
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
		rec.failOn = "bundle_chunk_v1_0001"
		rec.delay = 25 * time.Millisecond

		_, err := createFromLargeFile(t.Context(), client, path)
		require.ErrorContains(t, err, "bundle_chunk_v1_0001")
		// the first chunkConcurrency chunks start together, the remaining 5 of 10 must never start
		assert.LessOrEqual(t, rec.uploads, 5)

		_, err = rec.GetSealedRevisionFiles(rec.revisionID)
		require.ErrorContains(t, err, "not sealed")
	})

	t.Run("file truncated during the upload fails instead of uploading a short chunk", func(t *testing.T) {
		client, rec, path := setupLargeFileTest(t, content)
		var once sync.Once
		rec.onUpload = func() { once.Do(func() { require.NoError(t, os.Truncate(path, testChunkSize/2)) }) }

		_, err := createFromLargeFile(t.Context(), client, path)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)

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
	paths <- path
	close(paths)

	return client.CreateRevisionFromChan(ctx, paths, filepath.Dir(path))
}

func Test_CreateRevisionFromChan_LargeFile_MultipleFiles(t *testing.T) {
	client, rec, first := setupLargeFileTest(t, testContent(testChunkSize+1))
	dir := filepath.Dir(first)
	secondContent := testContent(2*testChunkSize + 3)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "other.txt"), secondContent, 0o600))

	paths := make(chan string, 2)
	paths <- first
	paths <- filepath.Join(dir, "other.txt")
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
	assert.Equal(t, string(secondContent[testChunkSize:2*testChunkSize]), byName["other.txt_chunk_v1_0001"])
	assert.Contains(t, byName, "bundle_chunk_v1_0001")
}

func Test_CreateRevisionFromChan_LargeFile_NoPaths(t *testing.T) {
	client, rec, path := setupLargeFileTest(t, testContent(1))

	paths := make(chan string)
	close(paths)

	_, err := client.CreateRevisionFromChan(t.Context(), paths, filepath.Dir(path))
	require.ErrorIs(t, err, fileupload.ErrNoFilesProvided)
	assert.Zero(t, rec.uploads)
}

func Test_CreateRevisionFromChan_LargeFile_RejectsContentTranscoder(t *testing.T) {
	rec := &recordingClient{FakeSealableClient: uploadrevision2.NewFakeSealableClient(uploadrevision2.FakeClientConfig{})}
	path := filepath.Join(t.TempDir(), "bundle")
	require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))

	// the options are order independent
	for name, opts := range map[string][]fileupload.Option{
		"transcoder first": {fileupload.WithContentTranscoder(func(c []byte) ([]byte, error) { return c, nil }), fileupload.WithLargeFileUpload(true)},
		"large file first": {fileupload.WithLargeFileUpload(true), fileupload.WithContentTranscoder(func(c []byte) ([]byte, error) { return c, nil })},
	} {
		t.Run(name, func(t *testing.T) {
			allOpts := append([]fileupload.Option{fileupload.WithUploadRevisionSealableClient(rec)}, opts...)
			client := fileupload.NewClient(nil, fileupload.Config{OrgID: uuid.New()}, allOpts...)

			_, err := createFromLargeFile(t.Context(), client, path)

			require.ErrorIs(t, err, fileupload.ErrContentTranscoderWithLargeFileUpload)
			assert.Zero(t, rec.uploads, "nothing must be uploaded")
		})
	}
}

func Test_CreateRevisionFromChan_LargeFile_NestedPathIsRelativeToRoot(t *testing.T) {
	client, rec, first := setupLargeFileTest(t, []byte("x"))
	root := filepath.Dir(first)
	require.NoError(t, os.MkdirAll(filepath.Join(root, "src", "pkg"), 0o700))
	nested := filepath.Join(root, "src", "pkg", "big.bin")
	require.NoError(t, os.WriteFile(nested, []byte("y"), 0o600))

	paths := make(chan string, 1)
	paths <- nested // an absolute filesystem path, like the batched upload receives
	close(paths)

	res, err := client.CreateRevisionFromChan(t.Context(), paths, root)
	require.NoError(t, err)
	assert.Equal(t, 1, res.UploadedFilesCount)

	files, err := rec.GetSealedRevisionFiles(res.RevisionID)
	require.NoError(t, err)
	require.Len(t, files, 1)
	assert.Equal(t, "src/pkg/big.bin_chunk_v1_0000", files[0].Path)
}
