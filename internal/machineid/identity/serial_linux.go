//go:build linux

package identity

import (
	"fmt"
	"os"
	"strings"
)

const linuxSerialPath = "/sys/class/dmi/id/product_serial"

// readSerialFromPath reads a raw hardware serial from path.
// Errors indicate the query failed (missing file, permission denied, etc.).
func readSerialFromPath(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read serial: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

func readSerialPlatform() (string, error) {
	return readSerialFromPath(linuxSerialPath)
}
