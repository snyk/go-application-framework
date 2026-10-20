package errorcatalog

import (
	"net/http"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ErrorFromHTTPStatus_Unauthorized(t *testing.T) {
	err, ok := ErrorFromHTTPStatus(http.StatusUnauthorized, "detail text")

	require.True(t, ok)
	assert.Equal(t, snyk.NewUnauthorisedError("").ErrorCode, err.ErrorCode)
	assert.Equal(t, "detail text", err.Detail)
}

func Test_ErrorFromHTTPStatus_BadRequest(t *testing.T) {
	err, ok := ErrorFromHTTPStatus(http.StatusBadRequest, "detail text")

	require.True(t, ok)
	assert.Equal(t, snyk.NewBadRequestError("").ErrorCode, err.ErrorCode)
}

func Test_ErrorFromHTTPStatus_TooManyRequests(t *testing.T) {
	err, ok := ErrorFromHTTPStatus(http.StatusTooManyRequests, "detail text")

	require.True(t, ok)
	assert.Equal(t, snyk.NewTooManyRequestsError("").ErrorCode, err.ErrorCode)
}

func Test_ErrorFromHTTPStatus_BadGateway(t *testing.T) {
	err, ok := ErrorFromHTTPStatus(http.StatusBadGateway, "detail text")

	require.True(t, ok)
	assert.Equal(t, snyk.NewBadGatewayError("").ErrorCode, err.ErrorCode)
}

func Test_ErrorFromHTTPStatus_ServiceUnavailable(t *testing.T) {
	err, ok := ErrorFromHTTPStatus(http.StatusServiceUnavailable, "detail text")

	require.True(t, ok)
	assert.Equal(t, snyk.NewServiceUnavailableError("").ErrorCode, err.ErrorCode)
}

func Test_ErrorFromHTTPStatus_InternalServerError(t *testing.T) {
	err, ok := ErrorFromHTTPStatus(http.StatusInternalServerError, "detail text")

	require.True(t, ok)
	assert.Equal(t, snyk.NewServerError("").ErrorCode, err.ErrorCode)
}

func Test_ErrorFromHTTPStatus_UnmappedStatusReportsNoMapping(t *testing.T) {
	err, ok := ErrorFromHTTPStatus(http.StatusTeapot, "detail text")

	assert.False(t, ok)
	assert.Equal(t, snyk_errors.Error{}, err)
}

func Test_ErrorFromHTTPStatus_Forbidden(t *testing.T) {
	err, ok := ErrorFromHTTPStatus(http.StatusForbidden, "detail text")

	require.True(t, ok)
	assert.Equal(t, snyk.NewUnauthorisedError("").ErrorCode, err.ErrorCode)
}
