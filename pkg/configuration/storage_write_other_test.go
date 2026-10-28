//go:build !unix && !windows

package configuration

import "io/fs"

var errRefusedRename = fs.ErrPermission
