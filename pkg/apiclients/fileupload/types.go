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
