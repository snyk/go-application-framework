package fileupload

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sync/errgroup"

	"github.com/snyk/go-application-framework/internal/api/fileupload/uploadrevision"
)

const (
	// maxLargeFileSize is the maximum size of a file accepted in large file upload mode (10 GB).
	maxLargeFileSize int64 = 10_000_000_000
	// chunkConcurrency is the number of chunks uploaded in parallel.
	chunkConcurrency = 5
	// chunkNameFormat is the name of a chunk: the file path followed by a 0-indexed, zero-padded chunk number.
	chunkNameFormat = "%s_chunk_%04d"
)

// largeFileClient is the Client used when WithLargeFileUpload is enabled. It uploads every file
// in chunks instead of uploading many small files in batches.
type largeFileClient struct {
	*HTTPClient
}

var _ Client = (*largeFileClient)(nil)

// CreateRevisionFromChan uploads all paths received from the channel in chunks (file paths are relative to rootPath),
// returning a revision ID. Each file is split into chunks named "<path>_chunk_NNNN".
// This is a convenience method that creates, uploads, and seals a revision.
func (c *largeFileClient) CreateRevisionFromChan(ctx context.Context, paths <-chan string, rootPath string) (UploadResult, error) {
	revisionID, err := c.createRevision(ctx)
	if err != nil {
		return UploadResult{}, err
	}

	res := UploadResult{RevisionID: revisionID, SkippedFiles: make([]SkippedFile, 0)}
	limits := c.uploadRevisionSealableClient.GetLimits()

	for path := range paths {
		if err := c.uploadLargeFileChunked(ctx, revisionID, rootPath, path, limits); err != nil {
			return UploadResult{}, fmt.Errorf("failed to add paths to revision %s: %w", revisionID, err)
		}
		res.UploadedFilesCount++
	}

	if res.UploadedFilesCount == 0 {
		return res, ErrNoFilesProvided
	}

	if err := c.sealRevision(ctx, revisionID); err != nil {
		return res, err
	}

	return res, nil
}

// chunk describes one chunk of the file.
type chunk struct {
	name   string
	offset int64
	length int64
}

// uploadLargeFileChunked splits the file at path into chunks and uploads them into an existing revision.
func (c *HTTPClient) uploadLargeFileChunked(ctx context.Context, revisionID RevisionID, rootPath, path string, limits uploadrevision.Limits) error {
	fullpath := filepath.Join(rootPath, path)
	file, size, err := openLargeFile(fullpath)
	if err != nil {
		return fmt.Errorf("failed to open large file: %w", err)
	}
	defer file.Close()

	chunkSize := limits.FileSizeLimit
	chunks, err := planChunks(path, size, chunkSize)
	if err != nil {
		return fmt.Errorf("failed to plan chunks for large file: %w", err)
	}

	//upload chunks
	if err := c.uploadChunks(ctx, revisionID, file, chunks); err != nil {
		return fmt.Errorf("failed to add chunks to revision %s: %w", revisionID, err)
	}

	return nil
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
					Path:   c.pathEncoder(p.name),
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

// planChunks splits size bytes of the file at path into chunks of chunkSize bytes; only the last chunk may be smaller.
func planChunks(path string, size, chunkSize int64) ([]chunk, error) {
	if chunkSize <= 0 {
		return nil, fmt.Errorf("invalid chunk size %d", chunkSize)
	}

	count := (size + chunkSize - 1) / chunkSize
	chunks := make([]chunk, 0, count)
	for i := int64(0); i < count; i++ {
		offset := i * chunkSize
		chunks = append(chunks, chunk{
			name:   fmt.Sprintf(chunkNameFormat, path, i),
			offset: offset,
			length: min(chunkSize, size-offset),
		})
	}

	return chunks, nil
}
