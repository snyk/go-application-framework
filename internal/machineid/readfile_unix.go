//go:build unix

package machineid

import "syscall"

const openNonBlocking = syscall.O_NONBLOCK
