package auth

import (
	"net/url"
	"strings"

	"github.com/snyk/go-application-framework/internal/api"
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
