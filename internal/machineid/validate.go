package machineid

import (
	"regexp"
	"strings"

	"github.com/snyk/go-application-framework/internal/machineid/identity"
)

// Hardware serials can contain spaces, so a space is allowed anywhere but at either end.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._:@ -]*[A-Za-z0-9._:@-])?$`)

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
	case len(id) > 128:
		return "longer than 128 characters", false
	case !idPattern.MatchString(id):
		return "contains characters outside the allowed set", false
	}
	if identity.NormalizeSerial(id) == "" {
		return "matches a known placeholder serial number", false
	}
	return "", true
}
