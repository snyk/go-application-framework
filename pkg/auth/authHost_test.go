package auth

import (
	"net/url"
	"testing"

	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
)

func Test_isValidAuthHost(t *testing.T) {
	testCases := []struct {
		authHost string
		expected bool
	}{
		{"api.au.snyk.io", true},
		{"api.example.snyk.io", true},
		{"api.snyk.io", true},
		{"api.snykgov.io", true},
		{"api.pre-release.snykgov.io", true},
		{"snyk.io", false},
		{"api.example.com", false},
		{"api.snyk.evil.com", false},
		{"evilsnykgov.io", false},
	}

	for _, tc := range testCases {
		actual, err := IsValidAuthHost(tc.authHost, constants.SNYK_DEFAULT_ALLOWED_HOST_REGEXP)
		assert.NoError(t, err)

		if actual != tc.expected {
			t.Errorf("isValidAuthHost(%q) = %v, want %v", tc.authHost, actual, tc.expected)
		}
	}
}

func Test_IsValidSnykHost(t *testing.T) {
	testCases := []struct {
		name     string
		host     string
		expected bool
	}{
		{"api.snyk.io", "api.snyk.io", true},
		{"api.au.snyk.io", "api.au.snyk.io", true},
		{"api.example.snyk.io", "api.example.snyk.io", true},
		{"api.snykgov.io", "api.snykgov.io", true},
		{"api.pre-release.snykgov.io", "api.pre-release.snykgov.io", true},
		{"case-insensitive", "API.SNYK.IO", true},
		{"multi-level subdomain", "api.a.b.c.snyk.io", true},
		{"https scheme prefixed host", "https://api.snyk.io", true},
		{"http scheme prefixed host", "http://api.snyk.io", true},
		{"non-http scheme rejected", "ftp://api.snyk.io", false},
		{"custom scheme rejected", "gopher://api.snyk.io", false},
		{"bare domain no api prefix", "snyk.io", false},
		{"domain not in allowlist", "api.example.com", false},
		{"suffix trick - domain as sub-suffix of evil host", "api.snyk.evil.com", false},
		{"missing label boundary prefix", "evilsnykgov.io", false},
		{"ticket attack host", "api.attacker-site.com", false},
		{"label boundary trick", "api.snykXsnyk.io", false},
		{"embedded domain as non-final label", "api.snyk.io.evil.com", false},
		{"embedded gov domain as non-final label", "api.snykgov.io.attacker.com", false},
		{"embedded domain then evil tld", "api.example.snyk.io.evil.com", false},
		{"embedded domain then attacker", "api.snyk.io.attacker.com", false},
		{"trailing dot", "api.snyk.io.", false},
		{"host with port", "api.snyk.io:8443", false},
		// Path/userinfo/whitespace smuggling: the allowlisted domain appears in
		// the input but not as the parsed host.
		{"path smuggle - trailing path", "api.snyk.io/haha", false},
		{"path smuggle - domain in path", "api.attacker.io/haha.snyk.io", false},
		{"userinfo smuggle", "token@api.snyk.io", false},
		{"whitespace smuggle", "api.something api.snyk.io", false},
		{"empty host", "", false},
	}

	allowedDomains := []string{"snyk.io", "snykgov.io"}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			conf := configuration.NewWithOpts()
			conf.Set(CONFIG_KEY_ALLOWED_HOSTS, allowedDomains)

			actual, err := IsValidSnykHost(conf, tc.host)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, actual, "IsValidSnykHost(%q)", tc.host)
		})
	}
}

func Test_IsValidSnykHost_EmptyAllowlistFailsClosed(t *testing.T) {
	conf := configuration.NewWithOpts()

	actual, err := IsValidSnykHost(conf, "api.snyk.io")
	assert.NoError(t, err)
	assert.False(t, actual, "empty allowlist should fail closed")
}

func Test_IsValidSnykHost_WhitespaceOnlyAllowlistFailsClosed(t *testing.T) {
	conf := configuration.NewWithOpts()
	conf.Set(CONFIG_KEY_ALLOWED_HOSTS, []string{"  "})

	actual, err := IsValidSnykHost(conf, "api.snyk.io")
	assert.NoError(t, err)
	assert.False(t, actual, "whitespace-only allowlist entries must be skipped and fail closed")
}

func Test_IsValidSnykHost_MixedEmptyAllowlistStillValidates(t *testing.T) {
	conf := configuration.NewWithOpts()
	conf.Set(CONFIG_KEY_ALLOWED_HOSTS, []string{"", "snyk.io"})

	actual, err := IsValidSnykHost(conf, "api.snyk.io")
	assert.NoError(t, err)
	assert.True(t, actual, "empty entries skipped, valid domain still matches")
}

func Test_parseHostURL(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		wantOK         bool
		wantNormalized string
		wantScheme     string
	}{
		{"bare host gets https", "api.snyk.io", true, "https://api.snyk.io", "https"},
		{"surrounding whitespace trimmed", "  api.snyk.io  ", true, "https://api.snyk.io", "https"},
		{"explicit https kept", "https://api.snyk.io", true, "https://api.snyk.io", "https"},
		{"explicit http kept", "http://api.snyk.io", true, "http://api.snyk.io", "http"},
		{"non-http scheme rejected", "ftp://api.snyk.io", false, "", ""},
		{"empty rejected", "", false, "", ""},
		{"internal whitespace rejected", "api snyk.io", false, "", ""},
		{"unparseable rejected", "http://[::1", false, "", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			normalized, parsed, ok := parseHostURL(tc.input)
			assert.Equal(t, tc.wantOK, ok)
			if !tc.wantOK {
				return
			}
			assert.Equal(t, tc.wantNormalized, normalized)
			assert.Equal(t, tc.wantScheme, parsed.Scheme)
		})
	}
}

// hostURL builds a *url.URL carrying only the given host, for exercising the
// url* helpers directly with hosts that parseHostURL would not accept.
func hostURL(host string) *url.URL {
	return &url.URL{Scheme: "https", Host: host}
}

func Test_urlIsHostOnly(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{"plain host", "api.snyk.io", true},
		{"trailing path", "api.snyk.io/haha", false},
		{"query", "api.snyk.io?x=1", false},
		{"fragment", "api.snyk.io#frag", false},
		{"userinfo", "token@api.snyk.io", false},
		{"port", "api.snyk.io:8443", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, parsed, ok := parseHostURL(tc.input)
			if !ok {
				assert.False(t, tc.expected, "parseHostURL rejected %q before urlIsHostOnly", tc.input)
				return
			}
			assert.Equal(t, tc.expected, urlIsHostOnly(parsed))
		})
	}
}

func Test_stringIsHostOnly(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{"plain host", "api.snyk.io", true},
		{"trailing path", "api.snyk.io/haha", false},
		{"query", "api.snyk.io?x=1", false},
		{"fragment", "api.snyk.io#frag", false},
		{"userinfo", "token@api.snyk.io", false},
		// A port survives the reconstruction because parsed.Host includes it;
		// it is urlIsHostOnly's job to reject the port. This documents the split.
		{"port matches reconstruction", "api.snyk.io:8443", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			normalized, parsed, ok := parseHostURL(tc.input)
			if !ok {
				assert.False(t, tc.expected, "parseHostURL rejected %q before stringIsHostOnly", tc.input)
				return
			}
			assert.Equal(t, tc.expected, stringIsHostOnly(normalized, parsed))
		})
	}
}

func Test_stringIsHostOnly_rejectsReconstructionMismatch(t *testing.T) {
	// A parsed URL whose fields look clean but whose reconstruction does not
	// match the normalized string must be rejected by the string cross-check.
	parsed := &url.URL{Scheme: "https", Host: "api.snyk.io"}
	assert.False(t, stringIsHostOnly("https://api.snyk.io/smuggled", parsed),
		"normalized string carrying more than scheme://host must be rejected")
	assert.True(t, stringIsHostOnly("https://api.snyk.io", parsed))
}

func Test_urlHasApiSubdomain(t *testing.T) {
	testCases := []struct {
		host     string
		expected bool
	}{
		{"api.snyk.io", true},
		{"api.au.snyk.io", true},
		{"API.SNYK.IO", true},
		{"api", false},
		{"snyk.io", false},
		{"xapi.snyk.io", false},
		{"apix.snyk.io", false},
		{"", false},
	}

	for _, tc := range testCases {
		t.Run(tc.host, func(t *testing.T) {
			assert.Equal(t, tc.expected, urlHasApiSubdomain(hostURL(tc.host)))
		})
	}
}

func Test_stringHasApiSubdomain(t *testing.T) {
	// Input is the lower-cased normalized string, as passed by IsValidSnykHost.
	testCases := []struct {
		lowerNormalized string
		expected        bool
	}{
		{"https://api.snyk.io", true},
		{"http://api.snyk.io", true},
		{"https://api.au.snyk.io", true},
		{"https://xapi.snyk.io", false},
		{"https://apix.snyk.io", false},
		{"https://snyk.io", false},
		{"https://api", false},
		{"ftp://api.snyk.io", false},
		{"api.snyk.io", false},
	}

	for _, tc := range testCases {
		t.Run(tc.lowerNormalized, func(t *testing.T) {
			assert.Equal(t, tc.expected, stringHasApiSubdomain(tc.lowerNormalized))
		})
	}
}

func Test_urlHasAllowedDomain(t *testing.T) {
	allowed := []string{"snyk.io", "snykgov.io"}
	testCases := []struct {
		name     string
		host     string
		domains  []string
		expected bool
	}{
		{"exact api.snyk.io", "api.snyk.io", allowed, true},
		{"regional subdomain", "api.au.snyk.io", allowed, true},
		{"gov domain", "api.snykgov.io", allowed, true},
		{"uppercase host", "API.SNYK.IO", allowed, true},
		{"domain not allowed", "api.example.com", allowed, false},
		{"embedded domain non-final", "api.snyk.io.evil.com", allowed, false},
		{"label boundary trick", "api.snykXsnyk.io", allowed, false},
		{"bare domain equals allowlist entry", "snyk.io", allowed, false},
		{"whitespace-only domains skipped", "api.snyk.io", []string{" "}, false},
		{"empty entry skipped, valid still matches", "api.snyk.io", []string{"", "snyk.io"}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, urlHasAllowedDomain(hostURL(tc.host), tc.domains))
		})
	}
}

func Test_stringHasAllowedDomain(t *testing.T) {
	allowed := []string{"snyk.io", "snykgov.io"}
	testCases := []struct {
		name            string
		lowerNormalized string
		domains         []string
		expected        bool
	}{
		{"exact api.snyk.io", "https://api.snyk.io", allowed, true},
		{"regional subdomain", "https://api.au.snyk.io", allowed, true},
		{"gov domain", "https://api.snykgov.io", allowed, true},
		{"domain not allowed", "https://api.example.com", allowed, false},
		{"embedded domain non-final", "https://api.snyk.io.evil.com", allowed, false},
		{"label boundary trick", "https://api.snykxsnyk.io", allowed, false},
		{"whitespace-only domains skipped", "https://api.snyk.io", []string{" "}, false},
		{"empty entry skipped, valid still matches", "https://api.snyk.io", []string{"", "snyk.io"}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, stringHasAllowedDomain(tc.lowerNormalized, tc.domains))
		})
	}
}

func Test_domainToLabels(t *testing.T) {
	testCases := []struct {
		name       string
		domain     string
		wantOK     bool
		wantLabels []string
	}{
		{"simple domain", "snyk.io", true, []string{"snyk", "io"}},
		{"trims and lowercases", "  SNYK.IO  ", true, []string{"snyk", "io"}},
		{"empty rejected", "", false, nil},
		{"whitespace-only rejected", "  ", false, nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			labels, ok := domainToLabels(tc.domain)
			assert.Equal(t, tc.wantOK, ok)
			if tc.wantOK {
				assert.Equal(t, tc.wantLabels, labels)
			}
		})
	}
}

func Test_hasLabelSuffix(t *testing.T) {
	testCases := []struct {
		name     string
		labels   []string
		suffix   []string
		expected bool
	}{
		{"multi-label suffix", []string{"api", "snyk", "io"}, []string{"snyk", "io"}, true},
		{"single-label suffix", []string{"api", "snyk", "io"}, []string{"io"}, true},
		{"mismatch in middle", []string{"api", "snyk", "io"}, []string{"x", "io"}, false},
		{"suffix longer than labels", []string{"io"}, []string{"snyk", "io"}, false},
		{"exact equality", []string{"snyk", "io"}, []string{"snyk", "io"}, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, hasLabelSuffix(tc.labels, tc.suffix))
		})
	}
}
