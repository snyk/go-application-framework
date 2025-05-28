package auth

import (
	"fmt"
	"math/rand"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

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

func isValidAuthHost(authHost string, hostRegularExpression string) (bool, error) {
	if len(hostRegularExpression) == 0 {
		return false, fmt.Errorf("regular expression to check host names must not be empty")
	}

	r, err := regexp.Compile(hostRegularExpression)
	if err != nil {
		return false, err
	}

	return r.MatchString(authHost), nil
}

// FilterSupportedPatRegions iterates a list of region URLs and filters out regions not supported by PAT.
// It returns a filtered slice of URL strings
func FilterSupportedPatRegions(regions []string, unsupportedRegions []string) []string {
	scheme := "https"
	filteredRegions := make([]string, 0, len(regions))

	for _, region := range regions {
		prefix := strings.Split(region, "://")
		if len(prefix) > 0 {
			scheme = prefix[0]
		}
		if len(unsupportedRegions) > 0 && slices.Contains(unsupportedRegions, region) {
			continue
		}

		host, err := redirectAuthHost(region)
		if err != nil {
			continue
		}

		formattedRegion := fmt.Sprintf("%s://%s", scheme, host)
		filteredRegions = append(filteredRegions, formattedRegion)
	}
	return filteredRegions
}

// ShuffleStrings takes []string, shuffles the elements and returns a new []string with the shuffled elements
func ShuffleStrings(originalSlice []string) []string {
	shuffledSlice := make([]string, len(originalSlice))
	copy(shuffledSlice, originalSlice)

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	for i := len(shuffledSlice) - 1; i > 0; i-- {
		j := r.Intn(i + 1)
		shuffledSlice[i], shuffledSlice[j] = shuffledSlice[j], shuffledSlice[i]
	}
	return shuffledSlice
}
