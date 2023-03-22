package api

import (
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

const (
	app_pattern string = "^app\\."
	api_pattern string = "^api\\."
	api_prefix  string = "api."
	app_prefix  string = "app."
	port_suffix string = ":[0-9]*$"
)

func isLocalhost(host string) bool {
	if strings.HasPrefix(host, "localhost") {
		return true
	}

	hostnameRegexp, _ := regexp.Compile(port_suffix)
	host = hostnameRegexp.ReplaceAllString(host, "")

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}

	return addr.IsLoopback()
}

func GetCanonicalApiUrlFromString(userDefinedUrl string) (string, error) {
	result := ""
	url, err := url.Parse(userDefinedUrl)
	if err != nil {
		return result, err
	}

	return GetCanonicalApiUrl(*url)
}

func GetCanonicalApiUrl(url url.URL) (string, error) {
	result := ""

	// for localhost we don't change the host, since there are no subdomains
	if isLocalhost(url.Host) {
		url.Path = strings.Replace(url.Path, "/v1", "", 1)
	} else {
		appRegexp, _ := regexp.Compile(app_pattern)
		url.Host = appRegexp.ReplaceAllString(url.Host, api_prefix)

		apiRegexp, _ := regexp.Compile(api_pattern)
		if !apiRegexp.MatchString(url.Host) {
			url.Host = api_prefix + url.Host
		}

		// clean path and fragment
		url.Path = ""
		url.Fragment = ""
		url.RawQuery = ""
	}

	result = url.String()
	return result, nil
}

func DeriveAppUrl(canonicalUrl string) (string, error) {
	result := ""
	url, err := url.Parse(canonicalUrl)
	if err != nil {
		return result, err
	}

	apiRegexp, _ := regexp.Compile(api_pattern)
	url.Host = apiRegexp.ReplaceAllString(url.Host, app_prefix)

	result = url.String()
	return result, nil
}
