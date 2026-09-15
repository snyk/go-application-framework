// Package fileperms defines shared file/directory permission constants. It is kept dependency-free
// so it can be imported by packages that pkg/utils itself depends on (e.g. pkg/configuration)
// without creating an import cycle.
package fileperms

import "io/fs"

const (
	FILEPERM_755 fs.FileMode = 0755 // Owner=rwx, Group=r-x, Other=r-x
	FILEPERM_666 fs.FileMode = 0666 // Owner=rw-, Group=rw-, Other=rw-
)
