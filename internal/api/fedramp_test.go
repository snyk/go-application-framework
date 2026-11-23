package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_IsFedramp(t *testing.T) {
	cases := []struct {
		name string
		url  string
		want bool
	}{
		{name: "subdomain of snykgov.io with path", url: "https://api.fedramp.snykgov.io/something/else", want: true},
		{name: "bare snykgov.io", url: "https://snykgov.io", want: true},
		{name: "commercial API host", url: "https://api.snyk.io/", want: false},
		{name: "look-alike that only shares the string suffix", url: "https://evilsnykgov.io", want: false},
		{name: "look-alike with a non-label prefix", url: "https://notsnykgov.io", want: false},
		{name: "snykgov.io as a non-final label", url: "https://snykgov.io.evil.example", want: false},
		{name: "explicit default port does not matter", url: "https://api.snykgov.io:443", want: true},
		{name: "non-default port does not matter", url: "https://api.snykgov.io:8443", want: true},
		{name: "uppercase host", url: "https://API.SNYKGOV.IO", want: true},
		{name: "one trailing dot on host is ignored", url: "https://api.snykgov.io.", want: true},
		{name: "two trailing dots on host do not match", url: "https://api.snykgov.io..", want: false},
		{name: "userinfo does not change the host", url: "https://user@api.snykgov.io/", want: true},
		{name: "schemeless host has no hostname", url: "api.snykgov.io", want: false},
		{name: "empty string", url: "", want: false},
		{name: "unparseable input", url: "://bad", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, IsFedramp(tc.url))
		})
	}
}
