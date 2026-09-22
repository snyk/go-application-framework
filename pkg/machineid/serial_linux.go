//go:build linux

package machineid

import (
	"context"
	"os"

	"github.com/rs/zerolog"
)

// dmiProductSerialPath is where the kernel exposes the DMI/SMBIOS product serial number. It is a
// variable so tests can point it at a fixture file instead of the real sysfs tree, which most
// distributions only let root read.
var dmiProductSerialPath = "/sys/class/dmi/id/product_serial"

// readHardwareSerial reads the DMI product serial number from sysfs. Most distributions restrict
// this file to root; a permission error is exactly as expected for an unprivileged caller and is
// reported as absent, not as an error, like any other missing source in this package's chain.
func readHardwareSerial(_ context.Context, logger *zerolog.Logger) (string, bool) {
	logger = effectiveLogger(logger)
	data, err := os.ReadFile(dmiProductSerialPath)
	if err != nil {
		switch {
		case os.IsPermission(err):
			logger.Debug().Str("path", dmiProductSerialPath).Msg("machine id: hardware serial number sysfs file is not readable by this process")
		case os.IsNotExist(err):
			logger.Debug().Str("path", dmiProductSerialPath).Msg("machine id: hardware serial number sysfs file does not exist")
		default:
			logger.Debug().Err(err).Str("path", dmiProductSerialPath).Msg("machine id: failed to read hardware serial number sysfs file")
		}
		return "", false
	}
	return string(data), true
}
