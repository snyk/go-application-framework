package fileupload

import "os"

type fileToFilter struct {
	Path string
	Stat os.FileInfo
}

// FilteredFile represents a file that was filtered.
// It includes the filtered file's path and the reason it was filtered.
type FilteredFile struct {
	Path   string
	Reason error
}

type filter func(fileToFilter) *FilteredFile
