package fileupload

import "os"

// fileToFilter represents the metadata about a file that a Filter function gets
// in order to decide if the file should be filtered or not.
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

// filter is the type definition for functions which are used to
// filter files before uploading.
// The function will get metadata about files in the form of FileToFilter
// and return a FilteredFile object if the file should be filtered, or nil otherwise.
type filter func(fileToFilter) *FilteredFile
