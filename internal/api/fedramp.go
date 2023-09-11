package api

import (
	"net/url"
	"strings"
)

const (
	fedRampHostSuffix string = "snykgov.io"
)

func IsFedramp(canonicalUrl string) bool {
	parsedUrl, err := url.Parse(canonicalUrl)
	if err != nil {
		return false
	}
	hostname := strings.ToLower(parsedUrl.Host)
	return strings.HasSuffix(hostname, fedRampHostSuffix)
}
