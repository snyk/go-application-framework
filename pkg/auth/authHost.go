package auth

import (
	"net/url"
	"strings"

	"github.com/snyk/go-application-framework/internal/api"
	"github.com/snyk/go-application-framework/pkg/utils"
)

func redirectAuthHost(instance string) (string, error) {
	// handle both cases if instance is a URL or just a host
	if !strings.HasPrefix(instance, "http") {
		instance = "https://" + instance
	}

	instanceUrl, err := url.Parse(instance)
	if err != nil {
		return "", err
	}

	canonicalizedInstanceUrl, err := api.GetCanonicalApiAsUrl(*instanceUrl)
	if err != nil {
		return "", err
	}

	return canonicalizedInstanceUrl.Host, nil
}

func IsValidAuthHost(instance string, redirectAuthHostRE string) (bool, error) {
	isValidHost, err := utils.MatchesRegex(instance, redirectAuthHostRE)
	if err != nil {
		return false, err
	}
	return isValidHost, nil
}
