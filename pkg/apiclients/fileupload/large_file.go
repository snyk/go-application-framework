package fileupload

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"golang.org/x/sync/errgroup"

	"github.com/snyk/go-application-framework/internal/api/fileupload/uploadrevision"
)

const (
	// maxLargeFileSize is the maximum size of a file accepted by CreateRevisionFromLargeFile (10 GB).
	maxLargeFileSize int64 = 10_000_000_000
	// chunkConcurrency is the number of chunks uploaded in parallel.
	chunkConcurrency = 5
	// chunkNameFormat is the name of a chunk, 0-indexed and zero-padded.
	chunkNameFormat = "__chunk__%04d"
)

// LargeFileClient uploads a single file which exceeds the per-file size limit of the upload API.
// The file is split into equally sized chunks, which are uploaded as individual files named
// __chunk__0000, __chunk__0001, ... and reassembled by the server.
type LargeFileClient interface {
	CreateRevisionFromLargeFile(ctx context.Context, path string) (LargeFileUploadResult, error)
}

var _ LargeFileClient = (*HTTPClient)(nil)

// NewLargeFileClient creates a new client for uploading large files in chunks.
func NewLargeFileClient(httpClient *http.Client, cfg Config, opts ...Option) LargeFileClient {
	return newHTTPClient(httpClient, cfg, opts...)
}

// chunk describes one chunk of the file.
type chunk struct {
	name   string
	offset int64
	length int64
}

// CreateRevisionFromLargeFile splits the file at path into chunks, uploads them into a new revision
// and seals it. This is a convenience method that creates, uploads, and seals a revision.
func (c *HTTPClient) CreateRevisionFromLargeFile(ctx context.Context, path string) (LargeFileUploadResult, error) {
	file, size, err := openLargeFile(path)
	if err != nil {
		return LargeFileUploadResult{}, err
	}
	defer file.Close()

	chunkSize := c.uploadRevisionSealableClient.GetLimits().FileSizeLimit
	chunks, err := planChunks(size, chunkSize)
	if err != nil {
		return LargeFileUploadResult{}, err
	}

	revisionID, err := c.createRevision(ctx)
	if err != nil {
		return LargeFileUploadResult{}, err
	}

	if err := c.uploadChunks(ctx, revisionID, file, chunks); err != nil {
		return LargeFileUploadResult{}, fmt.Errorf("failed to add chunks to revision %s: %w", revisionID, err)
	}

	if err := c.sealRevision(ctx, revisionID); err != nil {
		return LargeFileUploadResult{}, err
	}

	return LargeFileUploadResult{RevisionID: revisionID, Size: size, ChunkCount: len(chunks)}, nil
}

// uploadChunks uploads all chunks, at most chunkConcurrency at a time. The first error cancels the remaining chunks.
func (c *HTTPClient) uploadChunks(ctx context.Context, revisionID RevisionID, file *os.File, chunks []chunk) error {
	group, groupCtx := errgroup.WithContext(ctx)
	group.SetLimit(chunkConcurrency)

	for _, p := range chunks {
		group.Go(func() error {
			// Go blocks while the concurrency limit is reached, so a failure may have happened in the meantime.
			if err := groupCtx.Err(); err != nil {
				return fmt.Errorf("chunk %s not uploaded: %w", p.name, err)
			}

			err := c.uploadRevisionSealableClient.UploadFiles(groupCtx, c.cfg.OrgID, revisionID,
				[]uploadrevision.UploadFile{{
					Path:   p.name,
					Size:   p.length,
					Reader: io.NewSectionReader(file, p.offset, p.length),
				}})
			if err != nil {
				return fmt.Errorf("failed to upload chunk %s: %w", p.name, err)
			}
			return nil
		})
	}

	//nolint:wrapcheck // errors are already wrapped with the chunk name.
	return group.Wait()
}

// openLargeFile opens the file and validates it can be uploaded. The caller must close the returned file.
func openLargeFile(path string) (*os.File, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, uploadrevision.NewFileAccessError(path, err)
	}

	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, 0, uploadrevision.NewFileAccessError(path, err)
	}

	switch {
	case !info.Mode().IsRegular():
		file.Close()
		return nil, 0, uploadrevision.NewSpecialFileError(path, info.Mode())
	case info.Size() == 0:
		file.Close()
		return nil, 0, ErrNoFilesProvided
	case info.Size() > maxLargeFileSize:
		file.Close()
		return nil, 0, uploadrevision.NewFileSizeLimitError(path, info.Size(), maxLargeFileSize)
	}

	return file, info.Size(), nil
}

// planChunks splits size bytes into chunks of chunkSize bytes; only the last chunk may be smaller.
func planChunks(size, chunkSize int64) ([]chunk, error) {
	if chunkSize <= 0 {
		return nil, fmt.Errorf("invalid chunk size %d", chunkSize)
	}

	count := (size + chunkSize - 1) / chunkSize
	chunks := make([]chunk, 0, count)
	for i := int64(0); i < count; i++ {
		offset := i * chunkSize
		chunks = append(chunks, chunk{
			name:   fmt.Sprintf(chunkNameFormat, i),
			offset: offset,
			length: min(chunkSize, size-offset),
		})
	}

	return chunks, nil
}
