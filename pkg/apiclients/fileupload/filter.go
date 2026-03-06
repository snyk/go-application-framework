package fileupload

import "os"

// fileToFilter represents the metadata about a file that a Filter function gets
// in order to decide if the file should be filtered or not.
type fileToFilter struct {
	Path string
	Stat os.FileInfo
}

// SkippedFile represents a file that was skipped.
// It includes the skipped file's path and the reason it was skipped.
type SkippedFile struct {
	Path   string
	Reason error
}

// filter is the type definition for functions which are used to
// filter files before uploading.
// The function will get metadata about files in the form of fileToFilter
// and return a SkippedFile object if the file should be skipped, or nil otherwise.
type filter func(fileToFilter) *SkippedFile
