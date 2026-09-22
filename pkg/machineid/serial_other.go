//go:build !darwin && !linux && !windows

package machineid

import (
	"context"

	"github.com/rs/zerolog"
)

// readHardwareSerial reports the hardware serial number as absent on every platform this package
// has no reader for, so the chain falls through to its next source instead of erroring.
func readHardwareSerial(_ context.Context, _ *zerolog.Logger) (string, bool) {
	return "", false
}
