package api

import (
	"net/url"
	"regexp"
	"strings"
)

func GetCanonicalApiUrl(userDefinedUrl string) (string, error) {
	result := ""
	url, err := url.Parse(userDefinedUrl)
	if err != nil {
		return result, err
	}

	// for localhost we don't change the host, since there are no subdomains
	if !strings.Contains(url.Host, "localhost") {
		appRegexp, _ := regexp.Compile("^app\\.")
		url.Host = appRegexp.ReplaceAllString(url.Host, "api.")

		apiRegexp, _ := regexp.Compile("^api\\.")
		if !apiRegexp.MatchString(url.Host) {
			url.Host = "api." + url.Host
		}
	}

	// clean path and fragment
	url.Path = ""
	url.Fragment = ""
	url.RawQuery = ""

	result = url.String()

	return result, nil
}

func DeriveAppUrl(canocialUrl string) (string, error) {
	result := ""
	url, err := url.Parse(canocialUrl)
	if err != nil {
		return result, err
	}

	apiRegexp, _ := regexp.Compile("^api\\.")
	url.Host = apiRegexp.ReplaceAllString(url.Host, "app.")

	result = url.String()
	return result, nil
}
