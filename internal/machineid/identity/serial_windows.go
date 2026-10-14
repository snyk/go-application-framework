//go:build windows

package identity

import (
	"errors"
	"fmt"

	"github.com/yusufpapurcu/wmi"
)

type win32BIOS struct {
	SerialNumber string
}

// The BIOS registry key does not reliably hold the SMBIOS serial, so WMI is queried instead.
func readSerialPlatform() (string, error) {
	var bios []win32BIOS
	if err := wmi.Query("SELECT SerialNumber FROM Win32_BIOS", &bios); err != nil {
		return "", fmt.Errorf("wmi Win32_BIOS: %w", err)
	}
	if len(bios) == 0 {
		return "", errors.New("wmi Win32_BIOS: no results")
	}
	return bios[0].SerialNumber, nil
}
