//go:build windows

package configuration

import "golang.org/x/sys/windows"

// errRefusedRename is what replacing a file another process holds open reports.
var errRefusedRename error = windows.ERROR_SHARING_VIOLATION
