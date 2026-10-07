package machineid

import (
	"regexp"
	"strings"
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]*$`)

// placeholderSerials are values firmware tooling reports when no real serial was set.
var placeholderSerials = map[string]struct{}{
	"0":                      {},
	"none":                   {},
	"to be filled by o.e.m.": {},
	"system serial number":   {},
	"not applicable":         {},
	"not specified":          {},
	"default string":         {},
	"invalid":                {},
	"n/a":                    {},
}

func blank(raw string) bool {
	return strings.TrimSpace(raw) == ""
}

func valid(id string) bool {
	if len(id) > 128 || !idPattern.MatchString(id) {
		return false
	}
	_, placeholder := placeholderSerials[strings.ToLower(id)]
	return !placeholder
}

// invalidReason describes why valid rejected id, for logging only.
func invalidReason(id string) string {
	switch {
	case len(id) > 128:
		return "longer than 128 characters"
	case !idPattern.MatchString(id):
		return "contains characters outside the allowed set"
	default:
		return "matches a known placeholder serial number"
	}
}
