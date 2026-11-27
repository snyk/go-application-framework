package api

import (
	"net/url"
	"strings"
)

// MatchesOrigin reports whether u has the scheme and host of base and no userinfo.
// Hosts are compared as written; one trailing dot on u is ignored. The port is compared only when base names one; a default port counts as explicit.
func MatchesOrigin(u, base *url.URL) bool {
	if u.User != nil || !strings.EqualFold(u.Scheme, base.Scheme) {
		return false
	}
	if strings.TrimSuffix(u.Hostname(), ".") != base.Hostname() {
		return false
	}
	return base.Port() == "" || effectivePort(u) == base.Port()
}

// HasPathPrefix reports whether the path of u is the path of base or lies below it on a segment boundary.
func HasPathPrefix(u, base *url.URL) bool {
	prefix := strings.TrimSuffix(base.Path, "/")
	return prefix == "" || u.Path == prefix || strings.HasPrefix(u.Path, prefix+"/")
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	switch u.Scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	}
	return ""
}
