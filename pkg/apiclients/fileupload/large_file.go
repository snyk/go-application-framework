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
	// maxLargeFileSize is the maximum size of a file accepted by CreateRevisionFromLargeFile (10 GB).
	maxLargeFileSize int64 = 10_000_000_000
	// chunkConcurrency is the number of chunks uploaded in parallel.
	chunkConcurrency = 5
	// chunkNameFormat is the name of a chunk, 0-indexed and zero-padded.
	chunkNameFormat = "__history__/__chunk__%04d"
)

// chunk describes one chunk of the file.
type chunk struct {
	name   string
	offset int64
	length int64
}

// createLargeUploadFile splits the file at path into chunks, uploads them into a new revision
// and seals it. This is a convenience method that creates, uploads, and seals a revision.
func (c *HTTPClient) uploadLargeFileChunked(ctx context.Context, revisionID RevisionID, rootPath, path string, limits uploadrevision.Limits) error {
	fullpath := filepath.Join(rootPath, path)
	file, size, err := openLargeFile(fullpath)
	if err != nil {
		return fmt.Errorf("failed to open large file: %w", err)
	}
	defer file.Close()

	chunkSize := limits.FileSizeLimit
	chunks, err := planChunks(size, chunkSize)
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
