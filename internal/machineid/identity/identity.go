// Package identity provides hostname and hardware serial lookups for machine identification.
package identity

import (
	"fmt"
	"os"
	"time"
)

var serialQueryTimeout = 5 * time.Second

var readSerial = readSerialPlatform

// Hostname returns the system hostname.
func Hostname() (string, error) {
	return os.Hostname()
}

// SerialNumber returns the hardware serial number.
// An error means the query failed or timed out. An empty string with a nil error
// means no usable serial is available. On timeout the query is abandoned, not canceled:
// the Windows WMI query cannot be canceled and keeps running in the background.
func SerialNumber() (string, error) {
	query := readSerial
	type result struct {
		serial string
		err    error
	}
	results := make(chan result, 1)
	go func() {
		serial, err := query()
		results <- result{serial: serial, err: err}
	}()

	select {
	case r := <-results:
		if r.err != nil {
			return "", fmt.Errorf("read serial number: %w", r.err)
		}
		return NormalizeSerial(r.serial), nil
	case <-time.After(serialQueryTimeout):
		return "", fmt.Errorf("read serial number: no response after %v", serialQueryTimeout)
	}
}
