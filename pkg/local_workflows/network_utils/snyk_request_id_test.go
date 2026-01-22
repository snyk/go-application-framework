package network_utils

import (
	"net/http"
	"testing"

	"github.com/snyk/go-application-framework/internal/constants"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
)

func Test_AddRequestId(t *testing.T) {
	t.Run("Add missing snyk-request-id", func(t *testing.T) {
		config := configuration.NewInMemory()
		net := networking.NewNetworkAccess(config)
		config.Set(configuration.API_URL, constants.SNYK_DEFAULT_API_URL)

		// use method under test
		AddSnykRequestId(net)

		request, err := http.NewRequest(http.MethodGet, "https://api.snyk.io", nil)
		assert.NoError(t, err)

		err = net.AddHeaders(request)
		assert.NoError(t, err)

		actualValue := request.Header.Get("snyk-request-id")
		assert.NotEmpty(t, actualValue)
	})

	t.Run("Do not override snyk-request-id", func(t *testing.T) {
		config := configuration.NewInMemory()
		net := networking.NewNetworkAccess(config)
		config.Set(configuration.API_URL, "https://api.snyk.io")
		expectedValue := "pre-existing-id"

		// use method under test
		AddSnykRequestId(net)

		request, err := http.NewRequest(http.MethodGet, "https://api.snyk.io", nil)
		request.Header.Add("snyk-request-id", expectedValue)
		assert.NoError(t, err)

		err = net.AddHeaders(request)
		assert.NoError(t, err)

		actualValue := request.Header.Get("snyk-request-id")
		assert.Equal(t, expectedValue, actualValue)
	})
}
