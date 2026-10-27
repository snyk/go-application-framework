//go:build !unix

package machineenrollment

import "os"

func openWithoutBlocking(path string) (*os.File, error) {
	return os.Open(path)
}
