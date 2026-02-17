package fileupload

import (
	"github.com/snyk/go-application-framework/internal/api/fileupload/uploadrevision"
)

// Aliasing uploadRevisionSealableClient errors so that they're scoped to the fileupload package as well.

// Sentinel errors for common conditions.
var (
	ErrNoFilesProvided = uploadrevision.ErrNoFilesUploaded
	ErrEmptyOrgID      = uploadrevision.ErrEmptyOrgID
	ErrEmptyRevisionID = uploadrevision.ErrEmptyRevisionID
)

// FileSizeLimitError indicates a file exceeds the maximum allowed size.
type FileSizeLimitError = uploadrevision.FileSizeLimitError

// FilePathLengthLimitError indicates a file's path exceeds the maximum allowed size.
type FilePathLengthLimitError = uploadrevision.FilePathLengthLimitError

// FileCountLimitError indicates too many files were provided.
type FileCountLimitError = uploadrevision.FileCountLimitError

// TotalPayloadSizeLimitError indicates the total size of all files exceeds the maximum allowed payload size.
type TotalPayloadSizeLimitError = uploadrevision.TotalPayloadSizeLimitError

// FileAccessError indicates a file access permission issue.
type FileAccessError = uploadrevision.FileAccessError

// SpecialFileError indicates a path points to a special file (device, pipe, socket, etc.) instead of a regular file.
type SpecialFileError = uploadrevision.SpecialFileError

// HTTPError indicates an HTTP request/response error.
type HTTPError = uploadrevision.HTTPError

// MultipartError indicates an issue with multipart request handling.
type MultipartError = uploadrevision.MultipartError
