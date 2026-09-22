package machineid

import (
	"regexp"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// maxIDLength is the longest identifier value validate accepts.
const maxIDLength = 128

// idPattern matches an identifier consisting only of characters that are safe to carry unescaped
// in a header value and that no shared-file or legacy writer would need to escape.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]*$`)

// placeholderSentinels are values known to be emitted by BIOS/OEM tooling in place of a real
// hardware serial number, e.g. by dmidecode or wmic on a machine whose manufacturer never set one.
// Comparison against this set is case-insensitive.
var placeholderSentinels = map[string]struct{}{
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

// blank reports whether raw is empty once surrounding whitespace is discarded. It is used only to
// decide whether a candidate supplied anything worth validating at all, so that an unset input
// (the common case) does not produce a validation-rejection log line; the actual accept/reject
// decision for a non-blank candidate is always valid, never blank.
func blank(raw string) bool {
	return strings.TrimSpace(raw) == ""
}

// valid reports whether id is safe to adopt as the machine identifier: at most maxIDLength
// characters, drawn only from a charset that can never require escaping in an HTTP header value,
// and not one of the placeholder strings BIOS/OEM tooling emits in place of a real serial. The
// charset alone already guarantees the header-safety property (no CR/LF/control characters, no
// whitespace); httpguts.ValidHeaderFieldValue is checked explicitly anyway so that guarantee is
// verified rather than merely implied by the regex.
func valid(id string) bool {
	if len(id) < 1 || len(id) > maxIDLength {
		return false
	}
	if !idPattern.MatchString(id) {
		return false
	}
	if !httpguts.ValidHeaderFieldValue(id) {
		return false
	}
	_, placeholder := placeholderSentinels[strings.ToLower(id)]
	return !placeholder
}

// invalidReason describes why valid rejected id, for logging only; it is never used to make a
// decision.
func invalidReason(id string) string {
	switch {
	case len(id) < 1:
		return "empty"
	case len(id) > maxIDLength:
		return "longer than 128 characters"
	case !idPattern.MatchString(id):
		return "contains characters outside the allowed set"
	case !httpguts.ValidHeaderFieldValue(id):
		return "not a legal HTTP header field value"
	default:
		return "matches a known placeholder serial number"
	}
}
