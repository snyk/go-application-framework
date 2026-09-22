package machineid

import "regexp"

// ioregSerialLine matches the platform serial number line in `ioreg -rd1 -c IOPlatformExpertDevice`
// output, e.g. `"IOPlatformSerialNumber" = "C02ABC1DEF23"`. This is deliberately not
// IOPlatformUUID, which ioreg reports in the same output but is a per-install identifier rather
// than a hardware serial number.
var ioregSerialLine = regexp.MustCompile(`"IOPlatformSerialNumber"\s*=\s*"([^"]*)"`)

// parseIoregPlatformSerial extracts the platform serial number from ioreg output. It has no build
// tag so it can be unit-tested against captured sample output on any platform; only the subprocess
// invocation that produces this output is macOS-only (see serial_darwin.go).
func parseIoregPlatformSerial(output []byte) (string, bool) {
	m := ioregSerialLine.FindSubmatch(output)
	if m == nil {
		return "", false
	}
	return string(m[1]), true
}
