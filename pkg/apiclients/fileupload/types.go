package fileupload

import (
	"sync"

	"github.com/puzpuzpuz/xsync"

	"github.com/snyk/go-application-framework/pkg/apiclients/fileupload/uploadrevision"
)

// OrgID represents an organization identifier.
type OrgID = uploadrevision.OrgID

// RevisionID represents a revision identifier.
type RevisionID = uploadrevision.RevisionID

// Filters holds the filtering configuration for file uploads with thread-safe maps.
type Filters struct {
	supportedExtensions  *xsync.MapOf[string, bool]
	supportedConfigFiles *xsync.MapOf[string, bool]
	once                 sync.Once
	initErr              error
}

// UploadOptions configures the behavior of file upload operations.
type uploadOptions struct {
	SkipDeeproxyFiltering bool
}

// UploadResult respresents the result of the upload.
type UploadResult struct {
	RevisionID         RevisionID     // The ID of the revision which was created.
	UploadedFilesCount int            // The number of uploaded files.
	FilteredFiles      []FilteredFile // The list of files which were filtered.
}
