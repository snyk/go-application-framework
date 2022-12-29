package utils

import (
	"io/fs"
)

const (
	FILEPERM_755 fs.FileMode = 0755 // Owner=rwx, Group=r-x, Other=r-x
)
