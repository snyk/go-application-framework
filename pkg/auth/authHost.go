package auth

import (
	"net/url"
	"strings"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/utils"
)

func redirectAuthHost(instance string) (string, error) {
	// handle both cases if instance is a URL or just a host
	if !strings.HasPrefix(instance, "http") {
		instance = "https://" + instance
	}

	instanceUrl, err := url.Parse(instance)
	if err != nil {
		return "", err
	}

	canonicalizedInstanceUrl, err := api.GetCanonicalApiAsUrl(*instanceUrl)
	if err != nil {
		return "", err
	}

	return canonicalizedInstanceUrl.Host, nil
}

// IsValidAuthHost is superseded by IsValidSnykHost — no code within this
// module calls it anymore; OAuth callback host validation goes exclusively
// through IsValidSnykHost. It's exported public API, though, so other repos
// may still call it directly; it's kept for now so any such callers keep
// compiling while we confirm they've migrated off it, and will be removed in
// a follow-up once that's verified.
func IsValidAuthHost(instance string, redirectAuthHostRE string) (bool, error) {
	isValidHost, err := utils.MatchesRegex(instance, redirectAuthHostRE)
	if err != nil {
		return false, err
	}
	return isValidHost, nil
}

// IsValidSnykHost reports whether input resolves to an "api." subdomain of one
// of the domains configured under CONFIG_KEY_ALLOWED_HOSTS. It fails closed: if
// no allowlist is configured, nothing is considered valid.
//
// Validation runs as small, single-purpose steps: parse the input as a URL,
// confirm it carries nothing but a host, confirm the host's leading DNS label
// is "api", and confirm an allowlisted domain matches on DNS-label boundaries.
//
// Each step is checked twice with two independent techniques — a url* helper
// that inspects the parsed *url.URL, and a string* helper that inspects the raw
// normalized string — and both must agree. If the parsed URL and the raw string
// disagree (e.g. a parser quirk that hides a smuggled component), validation
// fails closed rather than slipping through.
func IsValidSnykHost(conf configuration.Configuration, input string) (bool, error) {
	allowedDomains := conf.GetStringSlice(CONFIG_KEY_ALLOWED_HOSTS)
	if len(allowedDomains) == 0 {
		return false, nil
	}

	normalized, parsed, ok := parseHostURL(input)
	if !ok {
		return false, nil
	}
	// String checks are case-insensitive on host/domain; stringIsHostOnly keeps
	// the original case because the scheme case matters to its reconstruction.
	lowerNormalized := strings.ToLower(normalized)

	if !urlIsHostOnly(parsed) || !stringIsHostOnly(normalized, parsed) {
		return false, nil
	}
	if !urlHasApiSubdomain(parsed) || !stringHasApiSubdomain(lowerNormalized) {
		return false, nil
	}
	if !urlHasAllowedDomain(parsed, allowedDomains) || !stringHasAllowedDomain(lowerNormalized, allowedDomains) {
		return false, nil
	}

	return true, nil
}

// parseHostURL normalizes input (trimmed, https:// prepended when schemeless)
// and parses it. It returns the normalized string alongside the parsed URL so
// callers can cross-check the two. Empty, whitespace-bearing, unparseable, or
// non-http(s) input is rejected.
func parseHostURL(input string) (string, *url.URL, bool) {
	input = strings.TrimSpace(input)
	// Any internal whitespace means this is not a single, well-formed host.
	if input == "" || strings.ContainsAny(input, " \t\r\n") {
		return "", nil, false
	}

	if !strings.Contains(input, "://") {
		input = "https://" + input
	}

	parsed, err := url.Parse(input)
	if err != nil {
		return "", nil, false
	}

	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", nil, false
	}

	return input, parsed, true
}

// urlIsHostOnly confirms the parsed URL carries nothing but a host: no userinfo,
// opaque, port, path, query, or fragment.
func urlIsHostOnly(parsed *url.URL) bool {
	if parsed.User != nil || parsed.Opaque != "" ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Port() != "" {
		return false
	}
	return parsed.Hostname() != ""
}

// stringIsHostOnly cross-checks, against the raw string, that the normalized
// input is exactly "scheme://host" — so any component urlIsHostOnly's field
// checks might miss still causes a mismatch and rejection.
func stringIsHostOnly(normalized string, parsed *url.URL) bool {
	return normalized == parsed.Scheme+"://"+parsed.Host
}

// urlHasApiSubdomain confirms the parsed host's leading DNS label is "api" and
// that a further domain follows it.
func urlHasApiSubdomain(parsed *url.URL) bool {
	host := strings.ToLower(parsed.Hostname())
	labels := strings.Split(host, ".")
	return len(labels) > 1 && labels[0] == api.API_PREFIX
}

// stringHasApiSubdomain confirms, from the raw normalized string alone, that the
// host begins with an "api." label under an http(s) scheme.
func stringHasApiSubdomain(lowerNormalized string) bool {
	apiLabel := api.API_PREFIX + "."
	return strings.HasPrefix(lowerNormalized, "http://"+apiLabel) ||
		strings.HasPrefix(lowerNormalized, "https://"+apiLabel)
}

// urlHasAllowedDomain confirms the parsed host ends with one of the allowed
// registrable domains on a DNS-label boundary, with at least the "api" label
// ahead of it.
func urlHasAllowedDomain(parsed *url.URL, allowedDomains []string) bool {
	labels := strings.Split(strings.ToLower(parsed.Hostname()), ".")
	for _, domain := range allowedDomains {
		domainLabels, ok := domainToLabels(domain)
		if !ok {
			continue
		}
		// Require at least one label (the "api" label) ahead of the domain, and
		// match on label boundaries rather than as a raw suffix.
		if len(labels) > len(domainLabels) && hasLabelSuffix(labels, domainLabels) {
			return true
		}
	}
	return false
}

// domainToLabels normalizes an allowlist entry and splits it into DNS labels,
// reporting ok=false for empty/whitespace-only entries so callers skip them.
func domainToLabels(domain string) ([]string, bool) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, false
	}
	return strings.Split(domain, "."), true
}

// hasLabelSuffix reports whether labels ends with suffix, comparing whole DNS
// labels (not characters), so "snykXsnyk.io" is not a suffix of "snyk.io".
func hasLabelSuffix(labels, suffix []string) bool {
	if len(suffix) > len(labels) {
		return false
	}
	offset := len(labels) - len(suffix)
	for i, s := range suffix {
		if labels[offset+i] != s {
			return false
		}
	}
	return true
}

// stringHasAllowedDomain cross-checks, from the raw normalized string, that it
// ends with "." plus one of the allowed domains. This is anchored at the host
// because stringIsHostOnly has already established the string is "scheme://host".
func stringHasAllowedDomain(lowerNormalized string, allowedDomains []string) bool {
	for _, domain := range allowedDomains {
		domain = strings.ToLower(strings.TrimSpace(domain))
		if domain == "" {
			continue
		}
		if strings.HasSuffix(lowerNormalized, "."+domain) {
			return true
		}
	}
	return false
}
