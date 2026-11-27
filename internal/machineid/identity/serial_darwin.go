//go:build darwin

package identity

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

const ioregSerialKey = "IOPlatformSerialNumber"

func readSerialPlatform() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), serialQueryTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", fmt.Errorf("ioreg: %w", err)
	}
	return parseIORegSerial(out)
}

// parseIORegSerial extracts IOPlatformSerialNumber from ioreg output.
// Returns an error when the key is absent or malformed; callers treat that as a
// serial query failure, not an empty/placeholder serial.
func parseIORegSerial(out []byte) (string, error) {
	for line := range strings.SplitSeq(string(out), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, ioregSerialKey) {
			continue
		}

		const prefix = `"` + ioregSerialKey + `" = "`
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := strings.TrimPrefix(line, prefix)
		before, _, ok := strings.Cut(rest, "\"")
		if !ok {
			continue
		}
		return before, nil
	}

	return "", fmt.Errorf("%s not found in ioreg output", ioregSerialKey)
}
