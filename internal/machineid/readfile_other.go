//go:build !unix

package machineid

// openNonBlocking is unset where a FIFO cannot appear at a file path.
const openNonBlocking = 0
