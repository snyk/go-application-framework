package fileupload

import (
	"errors"

	"github.com/snyk/go-application-framework/internal/api/fileupload/uploadrevision"
)

// Aliasing uploadRevisionSealableClient errors so that they're scoped to the fileupload package as well.

// Sentinel errors for common conditions.
var (
	ErrNoFilesProvided = uploadrevision.ErrNoFilesUploaded
	ErrEmptyOrgID      = uploadrevision.ErrEmptyOrgID
	ErrEmptyRevisionID = uploadrevision.ErrEmptyRevisionID
	// ErrContentTranscoderWithLargeFileUpload is returned when WithContentTranscoder and WithLargeFileUpload
	// are combined: chunks are raw byte ranges of the file on disk, so its content cannot be transcoded.
	ErrContentTranscoderWithLargeFileUpload = errors.New("content transcoder cannot be combined with large file upload")
)

// FileSizeLimitError indicates a file exceeds the maximum allowed size.
type FileSizeLimitError = uploadrevision.FileSizeLimitError

// FilePathLengthLimitError indicates a file's path exceeds the maximum allowed size.
type FilePathLengthLimitError = uploadrevision.FilePathLengthLimitError

// FileCountLimitError indicates too many files were provided.
type FileCountLimitError = uploadrevision.FileCountLimitError

// TotalPayloadSizeLimitError indicates the total size of all files exceeds the maximum allowed payload size.
type TotalPayloadSizeLimitError = uploadrevision.TotalPayloadSizeLimitError

// InvalidChunkSizeError indicates the size chunks are uploaded in is below the minimum.
type InvalidChunkSizeError = uploadrevision.InvalidChunkSizeError

// ChunkCountLimitError indicates a file would need more chunks than the maximum.
type ChunkCountLimitError = uploadrevision.ChunkCountLimitError

// FileAccessError indicates a file access permission issue.
type FileAccessError = uploadrevision.FileAccessError

// SpecialFileError indicates a path points to a special file (device, pipe, socket, etc.) instead of a regular file.
type SpecialFileError = uploadrevision.SpecialFileError

// SymlinkError indicates a path is a symbolic link, which is never followed, so its target is not uploaded.
// It is the upload client's counterpart of utils.SymlinkError and does not unwrap to it.
// FilePath is the root-relative (encoded) path.
type SymlinkError = uploadrevision.SymlinkError

// HTTPError indicates an HTTP request/response error.
type HTTPError = uploadrevision.HTTPError

// MultipartError indicates an issue with multipart request handling.
type MultipartError = uploadrevision.MultipartError
