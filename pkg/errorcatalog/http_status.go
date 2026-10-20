package errorcatalog

import (
	"net/http"

	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
)

// ErrorFromHTTPStatus maps an HTTP status code to the Error Catalog error that describes it.
// The detail text and options are applied to the returned error. The bool is false when the
// status has no catalog mapping, in which case the returned error is the zero value and the
// caller chooses its own fallback.
func ErrorFromHTTPStatus(status int, detail string, options ...snyk_errors.Option) (snyk_errors.Error, bool) {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return snyk.NewUnauthorisedError(detail, options...), true
	case http.StatusBadRequest:
		return snyk.NewBadRequestError(detail, options...), true
	case http.StatusTooManyRequests:
		return snyk.NewTooManyRequestsError(detail, options...), true
	case http.StatusBadGateway:
		return snyk.NewBadGatewayError(detail, options...), true
	case http.StatusServiceUnavailable:
		return snyk.NewServiceUnavailableError(detail, options...), true
	case http.StatusInternalServerError:
		return snyk.NewServerError(detail, options...), true
	}
	return snyk_errors.Error{}, false
}
