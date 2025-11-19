package filters //nolint:testpackage // Testing private utility functions.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

var orgID = uuid.MustParse("738ef92e-21cc-4a11-8c13-388d89272f4b")

func Test_getBaseUrl_notFedramp(t *testing.T) {
	actualURL := getFilterURL("https://api.snyk.io", orgID, false)
	assert.Equal(t, "https://deeproxy.snyk.io/filters", actualURL)
}

func Test_getBaseUrl_fedramp(t *testing.T) {
	actualURL := getFilterURL("https://api.snyk.io", orgID, true)
	assert.Equal(t, "https://api.snyk.io/hidden/orgs/738ef92e-21cc-4a11-8c13-388d89272f4b/code/filters", actualURL)
}
