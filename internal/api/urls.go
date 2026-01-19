package api

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

const (
	API_PREFIX   string = "api"
	appPattern   string = "^app\\."
	apiPattern   string = "^api\\."
	apiPrefixDot string = API_PREFIX + "."
	appPrefix    string = "app"
)

var (
	apiRegexp = regexp.MustCompile(apiPattern)
	appRegexp = regexp.MustCompile(appPattern)
)

func isImmutableHost(host string) bool {
	if IsKnownHostName(host) {
		return true
	}

	// ipv6 hosts must start with "["
	if strings.HasPrefix(host, "[") {
		return true
	}
	portlessHost := strings.Split(host, ":")[0]

	_, _, err := net.ParseCIDR(portlessHost + "/24")
	return err == nil
}

func IsKnownHostName(host string) bool {
	if strings.HasPrefix(host, "http") {
		parsedUrl, err := url.Parse(host)
		if err != nil {
			return false
		}
		host = parsedUrl.Host
	}

	knownHostNames := map[string]bool{
		"localhost": true,
		"127.0.0.1": true,
		"stella":    true,
	}

	// get rid of port
	portlessHost := strings.Split(host, ":")[0]

	return knownHostNames[portlessHost]
}

func GetCanonicalApiUrlFromString(userDefinedUrl string) (string, error) {
	result := ""
	url, err := url.Parse(userDefinedUrl)
	if err != nil {
		return result, err
	}

	return GetCanonicalApiUrl(*url)
}

func GetCanonicalApiAsUrl(url url.URL) (url.URL, error) {
	// for localhost we don't change the host, since there are no subdomains
	if isImmutableHost(url.Host) {
		url.Path = strings.Replace(url.Path, "/v1", "", 1)
	} else {
		url.Host = appRegexp.ReplaceAllString(url.Host, apiPrefixDot)

		if !apiRegexp.MatchString(url.Host) {
			url.Host = apiPrefixDot + url.Host
		}

		// clean path and fragment
		url.Path = ""
		url.Fragment = ""
		url.RawQuery = ""
	}

	return url, nil
}

func GetCanonicalApiUrl(url url.URL) (string, error) {
	result, err := GetCanonicalApiAsUrl(url)
	if err != nil {
		return "", err
	}

	return result.String(), nil
}

func DeriveAppUrl(canonicalUrl string) (string, error) {
	return DeriveSubdomainUrl(canonicalUrl, appPrefix)
}

func DeriveSubdomainUrl(canonicalUrl string, subdomain string) (string, error) {
	result := ""
	url, err := url.Parse(canonicalUrl)
	if err != nil {
		return result, err
	}

	url.Host = apiRegexp.ReplaceAllString(url.Host, subdomain+".")

	result = url.String()
	return result, nil
}
