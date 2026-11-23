package fileupload

import (
	"github.com/snyk/go-application-framework/internal/api/fileupload/uploadrevision"
)

// OrgID represents an organization identifier.
type OrgID = uploadrevision.OrgID

// RevisionID represents a revision identifier.
type RevisionID = uploadrevision.RevisionID

// UploadResult respresents the result of the upload.
type UploadResult struct {
	RevisionID         RevisionID    // The ID of the revision which was created.
	UploadedFilesCount int           // The number of uploaded files.
	SkippedFiles       []SkippedFile // The list of files which were skipped.
}

// LargeFileUploadResult represents the result of a large file upload.
type LargeFileUploadResult struct {
	RevisionID RevisionID // The ID of the revision which was created.
	Size       int64      // The size of the uploaded file in bytes.
	ChunkCount int        // The number of chunks the file was split into.
}
