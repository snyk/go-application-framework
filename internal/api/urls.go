package api

import (
	"net/url"
	"regexp"
	"strings"
)

const (
	app_pattern string = "^app\\."
	api_pattern string = "^api\\."
	api_prefix  string = "api."
	app_prefix  string = "app."
)

func GetCanonicalApiUrl(userDefinedUrl string) (string, error) {
	result := ""
	url, err := url.Parse(userDefinedUrl)
	if err != nil {
		return result, err
	}

	// for localhost we don't change the host, since there are no subdomains
	if strings.Contains(url.Host, "localhost") {
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
