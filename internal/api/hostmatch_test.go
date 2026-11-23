package api

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustParseUrl(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func TestMatchesOrigin(t *testing.T) {
	cases := []struct {
		name string
		u    string
		base string
		want bool
	}{
		{name: "same scheme and host match", u: "https://api.snyk.io/rest/orgs", base: "https://api.snyk.io", want: true},
		{name: "host comparison is case-sensitive", u: "https://API.Snyk.IO/", base: "https://api.snyk.io", want: false},
		{name: "host with an extra suffix label does not match", u: "https://api.snyk.io.evil.example/", base: "https://api.snyk.io", want: false},
		{name: "host that only shares a string prefix does not match", u: "https://api.snyk.iomalicious.example/", base: "https://api.snyk.io", want: false},
		{name: "host that is a suffix of the base does not match", u: "https://snyk.io/", base: "https://api.snyk.io", want: false},
		{name: "different scheme does not match", u: "http://api.snyk.io/", base: "https://api.snyk.io", want: false},
		{name: "userinfo is rejected for the same host", u: "https://user@api.snyk.io/", base: "https://api.snyk.io", want: false},
		{name: "base without port matches any port", u: "https://api.snyk.io:8443/", base: "https://api.snyk.io", want: true},
		{name: "base with explicit default port matches no port", u: "https://api.snyk.io/", base: "https://api.snyk.io:443", want: true},
		{name: "base without port matches explicit default port", u: "https://api.snyk.io:443/", base: "https://api.snyk.io", want: true},
		{name: "base with port rejects other port", u: "https://api.snyk.io:8443/", base: "https://api.snyk.io:443", want: false},
		{name: "base port must equal the effective port of the URL", u: "http://api.snyk.io/", base: "http://api.snyk.io:443", want: false},
		{name: "base with non-default port matches the same port", u: "http://127.0.0.1:8080/x", base: "http://127.0.0.1:8080", want: true},
		{name: "IPv6 host with port matches the same host", u: "http://[::1]:8080/x", base: "http://[::1]:8080", want: true},
		{name: "trailing dot on the host is ignored", u: "https://api.snyk.io./", base: "https://api.snyk.io", want: true},
		{name: "two trailing dots on the host do not match", u: "https://api.snyk.io../", base: "https://api.snyk.io", want: false},
		{name: "trailing dot on the base host is not ignored", u: "https://api.snyk.io/", base: "https://api.snyk.io.", want: false},
		{name: "non-ASCII lookalike host does not match", u: "https://api.dİgital.com/", base: "https://api.digital.com", want: false},
		{name: "bracketed IPv6 host matches the same address", u: "http://[::1]/", base: "http://[::1]", want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, MatchesOrigin(mustParseUrl(t, tc.u), mustParseUrl(t, tc.base)))
		})
	}
}

func TestHasPathPrefix(t *testing.T) {
	cases := []struct {
		name string
		u    string
		base string
		want bool
	}{
		{name: "base without path matches any path", u: "https://extension.example/anything", base: "https://extension.example", want: true},
		{name: "base with root path matches any path", u: "https://extension.example/anything", base: "https://extension.example/", want: true},
		{name: "base path matches exactly", u: "https://extension.example/code", base: "https://extension.example/code", want: true},
		{name: "base path matches a deeper segment", u: "https://extension.example/code/build", base: "https://extension.example/code", want: true},
		{name: "base path does not match a longer segment", u: "https://extension.example/codex", base: "https://extension.example/code", want: false},
		{name: "base path does not match a different leading segment", u: "https://extension.example/other/code", base: "https://extension.example/code", want: false},
		{name: "request without path does not match a base path", u: "https://extension.example", base: "https://extension.example/code", want: false},
		{name: "trailing slash on base is ignored for the exact path", u: "https://extension.example/code", base: "https://extension.example/code/", want: true},
		{name: "trailing slash on base is ignored for a deeper path", u: "https://extension.example/code/build", base: "https://extension.example/code/", want: true},
		{name: "trailing slash on base does not match a longer segment", u: "https://extension.example/codex", base: "https://extension.example/code/", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, HasPathPrefix(mustParseUrl(t, tc.u), mustParseUrl(t, tc.base)))
		})
	}
}

func TestIsSubdomainOf(t *testing.T) {
	cases := []struct {
		name   string
		host   string
		domain string
		want   bool
	}{
		{name: "one label ahead of the domain", host: "api.snyk.io", domain: "snyk.io", want: true},
		{name: "domain is trimmed and lowercased", host: "api.snyk.io", domain: "  SNYK.IO  ", want: true},
		{name: "single-label domain", host: "api.snyk.io", domain: "io", want: true},
		{name: "several labels ahead of the domain", host: "a.b.c.snyk.io", domain: "snyk.io", want: true},
		{name: "empty domain never matches", host: "api.snyk.io", domain: "", want: false},
		{name: "whitespace-only domain never matches", host: "api.snyk.io", domain: "  ", want: false},
		{name: "domain must match whole labels", host: "api.snykxsnyk.io", domain: "snyk.io", want: false},
		{name: "domain label must match exactly", host: "api.snyk.io", domain: "x.io", want: false},
		{name: "domain must be a suffix of the host", host: "api.snyk.io.evil.example", domain: "snyk.io", want: false},
		{name: "host equal to the domain is not a subdomain", host: "snyk.io", domain: "snyk.io", want: false},
		{name: "host shorter than the domain", host: "io", domain: "snyk.io", want: false},
		{name: "uppercase host is lowercased", host: "API.SNYK.IO", domain: "snyk.io", want: true},
		{name: "empty label in host is kept as in the label split", host: "api..snyk.io", domain: "snyk.io", want: true},
		{name: "trailing dot on host is not ignored", host: "api.snyk.io.", domain: "snyk.io", want: false},
		{name: "dot domain never matches", host: "api.snyk.io", domain: ".", want: false},
		{name: "double-dot domain never matches", host: "api.snyk.io", domain: "..", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsSubdomainOf(tc.host, tc.domain), "IsSubdomainOf(%q, %q)", tc.host, tc.domain)
		})
	}
}
