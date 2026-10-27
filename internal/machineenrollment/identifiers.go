package machineenrollment

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// IdentifierTypeSerialNumber is the type of a hardware serial number, the only identifier the
// enrollment service knows.
const IdentifierTypeSerialNumber = "serial_number"

// ErrUnsupportedPlatform is returned when this platform can't tell the serial numbers of the machine.
var ErrUnsupportedPlatform = errors.New("reading the machine's serial numbers is not supported on this platform")

// Identifier names a machine, as an admin registered it.
type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// IdentifierSource returns the identifiers of the machine it runs on: every one it can read.
type IdentifierSource func(ctx context.Context) ([]Identifier, error)

// SerialNumbers is the default IdentifierSource: the hardware serial numbers of this machine. It
// reads the platform serial number on macOS and the DMI product, board and chassis serial numbers
// on Linux (some of which need root), and fails with ErrUnsupportedPlatform elsewhere.
func SerialNumbers(ctx context.Context) ([]Identifier, error) {
	serials, err := readSerialNumbers(ctx)
	if err != nil {
		return nil, err
	}
	identifiers := serialIdentifiers(serials)
	if len(identifiers) == 0 {
		return nil, errors.New("found no serial number on this machine (reading them can need elevated permissions)")
	}
	return identifiers, nil
}

// placeholderSerials are values firmware reports when it has no serial number.
var placeholderSerials = []string{
	"", "0", "none", "n/a", "na", "unknown", "default string", "not specified", "not applicable",
	"not available", "system serial number", "to be filled by o.e.m.", "to be filled by oem",
}

// serialIdentifiers turns raw serial numbers into identifiers, leaving out placeholders and
// duplicates, and keeping their order.
func serialIdentifiers(serials []string) []Identifier {
	var identifiers []Identifier
	for _, serial := range serials {
		serial = strings.TrimSpace(serial)
		id := Identifier{Type: IdentifierTypeSerialNumber, Value: serial}
		if slices.Contains(placeholderSerials, strings.ToLower(serial)) ||
			slices.Contains(identifiers, id) || len(identifiers) == maxIdentifiers {
			continue
		}
		identifiers = append(identifiers, id)
	}
	return identifiers
}

// parseIoregSerial returns the platform serial number in the output of
// ioreg -rd1 -c IOPlatformExpertDevice, or "".
func parseIoregSerial(output string) string {
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != `"IOPlatformSerialNumber"` {
			continue
		}
		return strings.Trim(strings.TrimSpace(value), `"`)
	}
	return ""
}

// dmiSerialFiles are the serial numbers of the DMI table, as Linux exposes them. Some are readable
// by root only.
var dmiSerialFiles = []string{"product_serial", "board_serial", "chassis_serial"}

// readDMISerials reads the serial number files of dir, skipping those that are missing or unreadable.
func readDMISerials(dir string) []string {
	var serials []string
	for _, name := range dmiSerialFiles {
		if data, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			serials = append(serials, string(data))
		}
	}
	return serials
}
