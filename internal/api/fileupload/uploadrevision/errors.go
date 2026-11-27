package uploadrevision

import (
	"errors"
	"fmt"
	"os"
)

// Sentinel errors for common conditions.
var (
	ErrNoFilesUploaded = errors.New("no files uploaded")
	ErrEmptyOrgID      = errors.New("organization ID cannot be empty")
	ErrEmptyRevisionID = errors.New("revision ID cannot be empty")
)

// FileSizeLimitError indicates a file exceeds the maximum allowed size.
type FileSizeLimitError struct {
	FilePath string
	FileSize int64
	Limit    int64
}

func (e *FileSizeLimitError) Error() string {
	return fmt.Sprintf("file %s size %d exceeds limit of %d bytes", e.FilePath, e.FileSize, e.Limit)
}

// FileCountLimitError indicates too many files were provided.
type FileCountLimitError struct {
	Count int
	Limit int
}

func (e *FileCountLimitError) Error() string {
	return fmt.Sprintf("too many files: %d exceeds limit of %d", e.Count, e.Limit)
}

// TotalPayloadSizeLimitError indicates the total size of all files exceeds the maximum allowed payload size.
type TotalPayloadSizeLimitError struct {
	TotalSize int64
	Limit     int64
}

func (e *TotalPayloadSizeLimitError) Error() string {
	return fmt.Sprintf("total payload size %d bytes exceeds limit of %d bytes", e.TotalSize, e.Limit)
}

// FilePathLengthLimitError indicates a file path exceeds the maximum allowed length.
type FilePathLengthLimitError struct {
	FilePath string
	Length   int
	Limit    int
}

func (e *FilePathLengthLimitError) Error() string {
	return fmt.Sprintf("file name %s length %d exceeds limit of %d characters", e.FilePath, e.Length, e.Limit)
}

// FileAccessError indicates a file cannot be accessed or read.
type FileAccessError struct {
	FilePath string
	Err      error
}

func (e *FileAccessError) Error() string {
	return fmt.Sprintf("file %s cannot be accessed: %v", e.FilePath, e.Err)
}

func (e *FileAccessError) Unwrap() error {
	return e.Err
}

// HTTPError represents an HTTP error response.
type HTTPError struct {
	StatusCode int
	Status     string
	Operation  string
	Body       []byte
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("unsuccessful request to %s: %s", e.Operation, e.Status)
}

// MultipartError indicates an error creating multipart form data.
type MultipartError struct {
	FilePath string
	Err      error
}

func (e *MultipartError) Error() string {
	return fmt.Sprintf("failed to create multipart form for %s: %v", e.FilePath, e.Err)
}

func (e *MultipartError) Unwrap() error {
	return e.Err
}

// SpecialFileError indicates a path points to a special file (device, pipe, socket, etc.) instead of a regular file.
type SpecialFileError struct {
	FilePath string
	Mode     os.FileMode
}

func (e *SpecialFileError) Error() string {
	return fmt.Sprintf("path %s is not a regular file (mode: %s)", e.FilePath, e.Mode)
}

// SymlinkError indicates a path is a symbolic link, which is never followed, so its target is not uploaded.
// It is the upload client's counterpart of utils.SymlinkError and does not unwrap to it.
// FilePath is the root-relative (encoded) path.
type SymlinkError struct {
	FilePath string
}

func (e *SymlinkError) Error() string {
	return fmt.Sprintf("path %s is a symbolic link, which Snyk does not follow", e.FilePath)
}

// InvalidChunkSizeError indicates the size chunks are uploaded in is below the minimum.
// The chunk size is the file size limit of the upload service.
type InvalidChunkSizeError struct {
	ChunkSize int64
	MinSize   int64
}

func (e *InvalidChunkSizeError) Error() string {
	return fmt.Sprintf("invalid chunk size %d bytes: must be at least %d bytes", e.ChunkSize, e.MinSize)
}

// ChunkCountLimitError indicates a file would need more chunks than the maximum.
type ChunkCountLimitError struct {
	FilePath   string
	FileSize   int64
	ChunkSize  int64
	ChunkCount int64
	Limit      int64
}

func (e *ChunkCountLimitError) Error() string {
	return fmt.Sprintf("file %s of %d bytes needs %d chunks of %d bytes, exceeding the maximum of %d chunks",
		e.FilePath, e.FileSize, e.ChunkCount, e.ChunkSize, e.Limit)
}

// NewFileSizeLimitError creates a new FileSizeLimitError with the given parameters.
func NewFileSizeLimitError(filePath string, fileSize, limit int64) *FileSizeLimitError {
	return &FileSizeLimitError{
		FilePath: filePath,
		FileSize: fileSize,
		Limit:    limit,
	}
}

// NewFileCountLimitError creates a new FileCountLimitError with the given parameters.
func NewFileCountLimitError(count, limit int) *FileCountLimitError {
	return &FileCountLimitError{
		Count: count,
		Limit: limit,
	}
}

// NewTotalPayloadSizeLimitError creates a new TotalPayloadSizeLimitError with the given parameters.
func NewTotalPayloadSizeLimitError(totalSize, limit int64) *TotalPayloadSizeLimitError {
	return &TotalPayloadSizeLimitError{
		TotalSize: totalSize,
		Limit:     limit,
	}
}

// NewFileAccessError creates a new FileAccessError with the given parameters.
func NewFileAccessError(filePath string, err error) *FileAccessError {
	return &FileAccessError{
		FilePath: filePath,
		Err:      err,
	}
}

// NewHTTPError creates a new HTTPError with the given parameters.
func NewHTTPError(statusCode int, status, operation string, body []byte) *HTTPError {
	return &HTTPError{
		StatusCode: statusCode,
		Status:     status,
		Operation:  operation,
		Body:       body,
	}
}

// NewMultipartError creates a new MultipartError with the given parameters.
func NewMultipartError(filePath string, err error) *MultipartError {
	return &MultipartError{
		FilePath: filePath,
		Err:      err,
	}
}

// NewSpecialFileError creates a new SpecialFileError with the given path and mode.
func NewSpecialFileError(path string, mode os.FileMode) *SpecialFileError {
	return &SpecialFileError{
		FilePath: path,
		Mode:     mode,
	}
}

// NewSymlinkError creates a new SymlinkError with the given path.
func NewSymlinkError(path string) *SymlinkError {
	return &SymlinkError{FilePath: path}
}

// NewFilePathLengthLimitError creates a new FilePathLengthLimitError with the given parameters.
func NewFilePathLengthLimitError(filePath string, length, limit int) *FilePathLengthLimitError {
	return &FilePathLengthLimitError{
		FilePath: filePath,
		Length:   length,
		Limit:    limit,
	}
}

// NewInvalidChunkSizeError creates a new InvalidChunkSizeError with the given parameters.
func NewInvalidChunkSizeError(chunkSize, minSize int64) *InvalidChunkSizeError {
	return &InvalidChunkSizeError{
		ChunkSize: chunkSize,
		MinSize:   minSize,
	}
}

// NewChunkCountLimitError creates a new ChunkCountLimitError with the given parameters.
func NewChunkCountLimitError(filePath string, fileSize, chunkSize, chunkCount, limit int64) *ChunkCountLimitError {
	return &ChunkCountLimitError{
		FilePath:   filePath,
		FileSize:   fileSize,
		ChunkSize:  chunkSize,
		ChunkCount: chunkCount,
		Limit:      limit,
	}
}
