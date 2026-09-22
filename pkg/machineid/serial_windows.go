//go:build windows

package machineid

import (
	"context"

	"github.com/rs/zerolog"
	"golang.org/x/sys/windows/registry"
)

// biosSerialNumberKeyPath and biosSerialNumberValueName locate the BIOS system serial number the
// firmware exposes via ACPI/SMBIOS, mirrored into the registry by Windows at boot. Reading this
// value needs no subprocess, no COM, and no CIM/WMI: it is a plain registry read.
const (
	biosSerialNumberKeyPath   = `HARDWARE\DESCRIPTION\System\BIOS`
	biosSerialNumberValueName = "SystemSerialNumber"
)

// readHardwareSerial reads the BIOS system serial number from the registry. An absent key, an
// absent value, or an empty value are all reported as absent, exactly like an unreadable sysfs file
// on Linux, so the chain falls through to its next source rather than failing resolution.
func readHardwareSerial(_ context.Context, logger *zerolog.Logger) (string, bool) {
	logger = effectiveLogger(logger)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, biosSerialNumberKeyPath, registry.QUERY_VALUE)
	if err != nil {
		logger.Debug().Err(err).Msg("machine id: failed to open BIOS registry key for hardware serial number")
		return "", false
	}
	defer key.Close() //nolint:errcheck // a close failure on a key opened only for reading has nothing actionable to do

	value, _, err := key.GetStringValue(biosSerialNumberValueName)
	if err != nil {
		logger.Debug().Err(err).Msg("machine id: failed to read hardware serial number registry value")
		return "", false
	}
	return value, true
}
