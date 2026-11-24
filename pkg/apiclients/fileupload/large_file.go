package fileupload

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sync/errgroup"

	"github.com/snyk/go-application-framework/internal/api/fileupload/uploadrevision"
	"github.com/snyk/go-application-framework/pkg/utils"
)

const (
	// maxLargeFileSize is the maximum size of a file accepted in large file upload mode (10 GB).
	maxLargeFileSize int64 = 10_000_000_000
	// chunkConcurrency is the number of chunks uploaded in parallel.
	chunkConcurrency = 5
	// version is the contract version of the large file upload that defines the chunk naming,
	// that consumers can use to reassemble the original file
	version = "v1"
	// chunkNameFormat is the name of a chunk: the file path, contact version, followed by a 0-indexed, zero-padded chunk number.
	chunkNameFormat = "%s_chunk_%s_%04d"
	// maxChunkCount is the maximum number of chunks per file, bounded by the 4 digits of the chunk number
	// in chunkNameFormat (0000-9999). Beyond that, chunk names would no longer sort or be unique in width.
	maxChunkCount int64 = 10_000
	// minChunkSize is the smallest accepted chunk size (125 KB). Together with maxChunkCount it bounds
	// the size of files that can be uploaded and avoids uploading a file as a flood of tiny requests.
	minChunkSize int64 = 125_000
)

// largeFileClient is the Client used when WithLargeFileUpload is enabled. It uploads every file
// in chunks instead of uploading many small files in batches.
type largeFileClient struct {
	*HTTPClient
}

var _ Client = (*largeFileClient)(nil)

// CreateRevisionFromChan uploads all paths received from the channel in chunks (file paths are relative to rootPath),
// returning a revision ID. Each file is split into chunks named "<path>_chunk_v1_NNNN".
// This is a convenience method that creates, uploads, and seals a revision.
func (c *largeFileClient) CreateRevisionFromChan(ctx context.Context, paths <-chan string, rootPath string) (UploadResult, error) {
	// Chunks are raw byte ranges of the file on disk, so a transcoder would be silently ignored.
	// NewClient cannot return an error, so the combination is rejected before any revision is created.
	if c.contentTranscoder != nil {
		return UploadResult{}, ErrContentTranscoderWithLargeFileUpload
	}

	revisionID, err := c.createRevision(ctx)
	if err != nil {
		return UploadResult{}, err
	}

	res := UploadResult{RevisionID: revisionID, SkippedFiles: make([]SkippedFile, 0)}
	limits := c.uploadRevisionSealableClient.GetLimits()

	for path := range paths {
		// Like the batched upload, paths are filesystem paths; the name sent to the server is relative to rootPath.
		relPath, err := utils.ToRelativeUnixPath(rootPath, path)
		if err != nil {
			// relPath is not known, so the raw path is the best identifier available.
			c.logger.Debug().Err(err).Msgf("skipping file: %s", path)
			res.SkippedFiles = append(res.SkippedFiles, SkippedFile{Path: path, Reason: uploadrevision.NewFileAccessError(path, err)})
			continue
		}

		// Like the batched upload, skipped files are reported with the encoded path.
		encodedPath := c.pathEncoder(relPath)

		// A file that cannot be uploaded (missing, unreadable, special or too large) is skipped, not fatal.
		file, size, err := openLargeFile(path, encodedPath, maxLargeFileSize)
		if err != nil {
			c.logger.Debug().Err(err).Msgf("skipping file: %s", path)
			res.SkippedFiles = append(res.SkippedFiles, SkippedFile{Path: encodedPath, Reason: err})
			continue
		}

		chunks, err := planChunks(relPath, size, limits.FileSizeLimit, limits.FilePathLengthLimit, c.pathEncoder)
		if err != nil {
			_ = file.Close()

			// An invalid chunk size is a general limitation that applies to every file, so it is fatal.
			// Any other planning failure (name too long, too many chunks) is specific to this file.
			var chunkSizeErr *uploadrevision.InvalidChunkSizeError
			if errors.As(err, &chunkSizeErr) {
				return UploadResult{}, fmt.Errorf("failed to plan chunks for large file: %w", err)
			}

			c.logger.Debug().Err(err).Msgf("skipping file: %s", path)
			res.SkippedFiles = append(res.SkippedFiles, SkippedFile{Path: encodedPath, Reason: err})
			continue
		}

		err = c.uploadChunks(ctx, revisionID, file, chunks)
		_ = file.Close() // read-only file, a close error is not actionable
		if err != nil {
			return UploadResult{}, fmt.Errorf("failed to add paths to revision %s: failed to upload chunks: %w", revisionID, err)
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
					Reader: newChunkReader(file, p),
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

// chunkReader reads exactly the bytes of one chunk. The chunk length is fixed when the file is
// stat-ed, so a file truncated during the upload would otherwise end the section early, which
// io.Copy treats as success and uploads a short chunk. Reading less than the chunk length is an error.
type chunkReader struct {
	section *io.SectionReader
	chunk   chunk
	read    int64
}

func newChunkReader(file io.ReaderAt, c chunk) *chunkReader {
	return &chunkReader{section: io.NewSectionReader(file, c.offset, c.length), chunk: c}
}

func (r *chunkReader) Read(p []byte) (int, error) {
	n, err := r.section.Read(p)
	r.read += int64(n)

	if errors.Is(err, io.EOF) && r.read < r.chunk.length {
		return n, fmt.Errorf("chunk %s ended after %d of %d bytes, the file changed during the upload: %w",
			r.chunk.name, r.read, r.chunk.length, io.ErrUnexpectedEOF)
	}

	return n, err //nolint:wrapcheck // io.EOF must be returned unwrapped
}

// openLargeFile opens the file at path and validates it is a regular file of at most maxSize bytes.
// Errors identify the file by name (the root-relative path), matching the path of the skipped file entry.
// The caller must close the returned file.
func openLargeFile(path, name string, maxSize int64) (*os.File, int64, error) {
	// Opening a special file such as a named pipe blocks until a writer appears and cannot be interrupted
	// by cancellation, so the file type is decided before it is opened, like in the batched upload.
	pre, err := os.Stat(path)
	if err != nil {
		return nil, 0, uploadrevision.NewFileAccessError(name, err)
	}
	if !pre.Mode().IsRegular() {
		return nil, 0, uploadrevision.NewSpecialFileError(name, pre.Mode())
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, 0, uploadrevision.NewFileAccessError(name, err)
	}

	// The file may have been replaced between the stat above and the open, so the opened file is checked again.
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, 0, uploadrevision.NewFileAccessError(name, err)
	}

	switch {
	case !info.Mode().IsRegular():
		file.Close()
		return nil, 0, uploadrevision.NewSpecialFileError(name, info.Mode())
	case info.Size() > maxSize:
		file.Close()
		return nil, 0, uploadrevision.NewFileSizeLimitError(name, info.Size(), maxSize)
	}

	return file, info.Size(), nil
}

// planChunks splits size bytes of the file at path into chunks of chunkSize bytes; only the last chunk may be smaller.
// Every chunk name, as sent after encoding, must fit into nameLengthLimit, so that a name that is too long fails
// here instead of after part of the file has been uploaded.
func planChunks(path string, size, chunkSize int64, nameLengthLimit int, encode PathEncoder) ([]chunk, error) {
	if chunkSize < minChunkSize {
		return nil, uploadrevision.NewInvalidChunkSizeError(chunkSize, minChunkSize)
	}

	// An empty file is uploaded as a single zero-length chunk so that it still appears in the revision.
	count := max(1, (size+chunkSize-1)/chunkSize)
	if count > maxChunkCount {
		return nil, uploadrevision.NewChunkCountLimitError(path, size, chunkSize, count, maxChunkCount)
	}

	// All chunk numbers have the same width, so all names of a file have the same length.
	if name := encode(fmt.Sprintf(chunkNameFormat, path, version, int64(0))); len(name) > nameLengthLimit {
		return nil, uploadrevision.NewFilePathLengthLimitError(name, len(name), nameLengthLimit)
	}

	chunks := make([]chunk, 0, count)
	for i := int64(0); i < count; i++ {
		offset := i * chunkSize
		chunks = append(chunks, chunk{
			name:   fmt.Sprintf(chunkNameFormat, path, version, i),
			offset: offset,
			length: min(chunkSize, size-offset),
		})
	}

	return chunks, nil
}
