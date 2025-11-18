package uploadrevision

import (
	"io/fs"

	"github.com/google/uuid"
)

// OrgID represents an organization identifier.
type OrgID = uuid.UUID

// RevisionID represents a revision identifier.
type RevisionID = uuid.UUID

// RevisionType represents the type of revision being created.
type RevisionType string

const (
	// RevisionTypeSnapshot represents a snapshot revision type.
	RevisionTypeSnapshot RevisionType = "snapshot"
)

// ResourceType represents the type of resource in API requests.
type ResourceType string

const (
	// ResourceTypeUploadRevision represents an upload revision resource type.
	ResourceTypeUploadRevision ResourceType = "upload_revision"
)

// RequestAttributes contains the attributes for creating an upload revision.
type RequestAttributes struct {
	RevisionType RevisionType `json:"revision_type"` //nolint:tagliatelle // API expects snake_case
}

// RequestData contains the data payload for creating an upload revision.
type RequestData struct {
	Attributes RequestAttributes `json:"attributes"`
	Type       ResourceType      `json:"type"`
}

// RequestBody contains the complete request body for creating an upload revision.
type RequestBody struct {
	Data RequestData `json:"data"`
}

// ResponseAttributes contains the attributes returned when creating an upload revision.
type ResponseAttributes struct {
	RevisionType RevisionType `json:"revision_type"` //nolint:tagliatelle // API expects snake_case
	Sealed       bool         `json:"sealed"`
}

// ResponseData contains the data returned when creating an upload revision.
type ResponseData struct {
	ID         RevisionID         `json:"id"`
	Type       ResourceType       `json:"type"`
	Attributes ResponseAttributes `json:"attributes"`
}

// ResponseBody contains the complete response body when creating an upload revision.
type ResponseBody struct {
	Data ResponseData `json:"data"`
}

// SealRequestAttributes contains the attributes for sealing an upload revision.
type SealRequestAttributes struct {
	Sealed bool `json:"sealed"`
}

// SealRequestData contains the data payload for sealing an upload revision.
type SealRequestData struct {
	ID         RevisionID            `json:"id"`
	Type       ResourceType          `json:"type"`
	Attributes SealRequestAttributes `json:"attributes"`
}

// SealRequestBody contains the complete request body for sealing an upload revision.
type SealRequestBody struct {
	Data SealRequestData `json:"data"`
}

// SealResponseAttributes contains the attributes returned when sealing an upload revision.
type SealResponseAttributes struct {
	RevisionType RevisionType `json:"revision_type"` //nolint:tagliatelle // API expects snake_case
	Sealed       bool         `json:"sealed"`
}

// SealResponseData contains the data returned when sealing an upload revision.
type SealResponseData struct {
	ID         RevisionID             `json:"id"`
	Type       ResourceType           `json:"type"`
	Attributes SealResponseAttributes `json:"attributes"`
}

// SealResponseBody contains the complete response body when sealing an upload revision.
type SealResponseBody struct {
	Data SealResponseData `json:"data"`
}

// ResponseError represents an error in an API response.
type ResponseError struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

// ErrorResponseBody contains the complete error response body.
type ErrorResponseBody struct {
	Errors []ResponseError `json:"errors"`
}

// UploadFile represents a file to be uploaded, containing both the path and file handle.
type UploadFile struct {
	Path string // The path of the uploaded file, relative to the root directory.
	File fs.File
}

const (
	// ContentType is the HTTP header name for content type.
	ContentType = "Content-Type"
	// ContentEncoding is the HTTP header name for content encoding.
	ContentEncoding = "Content-Encoding"
	// ContentLength is the HTTP header name for content length.
	ContentLength = "Content-Length"
)

// Limits contains the limits enforced by the low level client.
type Limits struct {
	// FileCountLimit specifies the maximum number of files allowed in a single upload.
	FileCountLimit int
	// FileSizeLimit specifies the maximum allowed file size in bytes.
	FileSizeLimit int64
	// TotalPayloadSizeLimit specifies the maximum total uncompressed payload size in bytes.
	TotalPayloadSizeLimit int64
	// FilePathLengthLimit specifies the maximum allowed file name length in characters.
	FilePathLengthLimit int
}
