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

// IsSubdomainOf reports whether host is below domain on DNS-label boundaries, with at least one extra label.
// Both are lowercased, and the domain is also trimmed of surrounding space.
func IsSubdomainOf(host, domain string) bool {
	host = strings.ToLower(host)
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	hostLabels := strings.Split(host, ".")
	domainLabels := strings.Split(domain, ".")
	if len(hostLabels) <= len(domainLabels) {
		return false
	}
	offset := len(hostLabels) - len(domainLabels)
	for i, label := range domainLabels {
		if hostLabels[offset+i] != label {
			return false
		}
	}
	return true
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
