package machineid

import (
	"fmt"
	"regexp"
	"strings"
)

const maxIDLength = 128

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
	_, ok := validate(id)
	return ok
}

// validate reports whether id is a usable machine id and, if not, why, for logging.
func validate(id string) (reason string, ok bool) {
	switch {
	case len(id) > maxIDLength:
		return fmt.Sprintf("longer than %d characters", maxIDLength), false
	case !idPattern.MatchString(id):
		return "contains characters outside the allowed set", false
	}
	if _, placeholder := placeholderSerials[strings.ToLower(id)]; placeholder {
		return "matches a known placeholder serial number", false
	}
	return "", true
}
