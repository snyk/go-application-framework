package api

import (
	"net"
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
)

func isImmutableHost(host string) bool {
	knownHostNames := map[string]bool{
		"localhost": true,
		"stella":    true,
	}

	// get rid of port
	portlessHost := strings.Split(host, ":")[0]

	if knownHostNames[portlessHost] {
		return true
	}

	// ipv6 hosts must start with "["
	if strings.HasPrefix(host, "[") {
		return true
	}

	_, _, err := net.ParseCIDR(portlessHost + "/24")
	if err == nil {
		return true
	}

	return false
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
	var result string

	// for localhost we don't change the host, since there are no subdomains
	if isImmutableHost(url.Host) {
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
