package api

import (
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

const (
	API_PREFIX     string = "api"
	app_pattern    string = "^app\\."
	api_pattern    string = "^api\\."
	api_prefix_dot string = API_PREFIX + "."
	app_prefix     string = "app"
	port_suffix    string = ":[0-9]*$"
	stella_host    string = "stella:8000"
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

func isUsingStella (host string) bool {
	return strings.HasPrefix(host, stella_host)
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
	if isLocalhost(url.Host) || isUsingStella(url.Host) {
		url.Path = strings.Replace(url.Path, "/v1", "", 1)
	} else {
		appRegexp, _ := regexp.Compile(app_pattern)
		url.Host = appRegexp.ReplaceAllString(url.Host, api_prefix_dot)

		apiRegexp, _ := regexp.Compile(api_pattern)
		if !apiRegexp.MatchString(url.Host) {
			url.Host = api_prefix_dot + url.Host
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
	return DeriveSubdomainUrl(canonicalUrl, app_prefix)
}

func DeriveSubdomainUrl(canonicalUrl string, subdomain string) (string, error) {
	result := ""
	url, err := url.Parse(canonicalUrl)
	if err != nil {
		return result, err
	}

	apiRegexp, _ := regexp.Compile(api_pattern)
	url.Host = apiRegexp.ReplaceAllString(url.Host, subdomain+".")

	result = url.String()
	return result, nil
}
