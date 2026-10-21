package identity

import "strings"

// knownPlaceholderSerials holds the sentinel values firmware leaves in the serial
// field on VMs and some OEM hardware. Keys are lowercase.
var knownPlaceholderSerials = map[string]struct{}{
	"0":                      {},
	"none":                   {},
	"to be filled by o.e.m.": {},
	"to be filled by oem":    {},
	"system serial number":   {},
	"chassis serial number":  {},
	"default string":         {},
	"not specified":          {},
	"not applicable":         {},
	"invalid":                {},
	"n/a":                    {},
}

// serialFromBIOS guards against a nil pointer, which only a wmi client with PtrNil set produces.
// The default client returns a pointer to "" for a VT_NULL property.
func serialFromBIOS(raw *string) string {
	if raw == nil {
		return ""
	}
	return *raw
}

// NormalizeSerial returns the trimmed serial, or "" when raw is empty or a known placeholder.
func NormalizeSerial(raw string) string {
	serial := strings.TrimSpace(raw)
	if serial == "" {
		return ""
	}
	if _, ok := knownPlaceholderSerials[strings.ToLower(serial)]; ok {
		return ""
	}
	return serial
}
