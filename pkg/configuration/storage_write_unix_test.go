//go:build unix

package configuration

import "syscall"

// errRefusedRename is what replacing a bind-mounted file reports.
var errRefusedRename error = syscall.EBUSY
