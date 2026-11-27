package ufm_helpers

import (
	"strings"

	"github.com/google/uuid"
)

// sarifGUIDNamespace is the UUIDv5 namespace for every GUID this package derives.
// It is a fixed value: changing it changes every derived GUID, so never change it.
var sarifGUIDNamespace = uuid.MustParse("fc53eda7-fe1f-4844-8595-51ef320b9663")

// KindSuppression identifies GUIDs derived from the persistent identifier of an
// ignore (the policy rule behind a suppression).
const KindSuppression = "suppression"

// guidPartSeparator joins the derivation input. It cannot occur in a UUID or in
// a kind, so different part lists never produce the same input.
const guidPartSeparator = "\x1f"

// StableSARIFGUID returns the value to use for a SARIF "guid" property, or ""
// when the property must be omitted.
//
// A SARIF guid is a long-term identity and the SARIF schema only accepts UUID
// versions 1 to 5. The version of a backend UUID says nothing about whether it
// is stable (an ID minted during a single test run is not), so backend UUIDs
// are never forwarded. The result is always a UUIDv5 derived from the given
// persistent identifiers, which are only valid if they were created together
// with the thing they identify, not while a test ran.
//
// It returns "" if no part is given, or if any part is blank or the nil UUID,
// because deriving an identity from missing data would produce a value that
// looks stable but is shared by unrelated things. Parts that are UUIDs are
// normalised, so the same ID in a different notation yields the same GUID.
//
// The function is pure and safe for concurrent use.
func StableSARIFGUID(kind string, parts ...string) string {
	if strings.TrimSpace(kind) == "" || len(parts) == 0 {
		return ""
	}

	normalised := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if id, err := uuid.Parse(part); err == nil {
			if id == uuid.Nil {
				return ""
			}
			part = id.String()
		}
		if part == "" {
			return ""
		}
		normalised = append(normalised, part)
	}

	name := kind + guidPartSeparator + strings.Join(normalised, guidPartSeparator)
	return uuid.NewSHA1(sarifGUIDNamespace, []byte(name)).String()
}
