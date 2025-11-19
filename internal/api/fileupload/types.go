package fileupload

import (
	"sync"

	"github.com/puzpuzpuz/xsync"
)

// Filters holds the filtering configuration for file uploads with thread-safe maps.
type Filters struct {
	SupportedExtensions  *xsync.MapOf[string, bool]
	SupportedConfigFiles *xsync.MapOf[string, bool]
	Once                 sync.Once
	InitErr              error
}
