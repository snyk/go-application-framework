package middleware

import (
	"errors"
	"net/http"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	networktypes "github.com/snyk/go-application-framework/pkg/networking/network_types"
)

// NetworkStackErrorHandlerMiddleware is a middleware that handles network errors that are not yet error catalog errors.
type NetworkStackErrorHandlerMiddleware struct {
	next       http.RoundTripper
	errHandler networktypes.ErrorHandlerFunc
}

func NewNetworkStackErrorHandlerMiddleware(roundTriper http.RoundTripper, errHandler networktypes.ErrorHandlerFunc) *NetworkStackErrorHandlerMiddleware {
	return &NetworkStackErrorHandlerMiddleware{
		next:       roundTriper,
		errHandler: errHandler,
	}
}

func (ns *NetworkStackErrorHandlerMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := ns.next.RoundTrip(req)

	if err != nil {
		// handle error that are not yet error catalog errors
		var snykError snyk_errors.Error
		if !errors.Is(err, &snykError) {
			// TODO: replace with snyk_errors.NewNetworkError when available
			err = snyk_errors.Error{
				Title:          "Network Error",
				Description:    "An error occurred while making a network request.",
				Detail:         "Request URL: " + req.URL.String() + "\n" + err.Error(),
				StatusCode:     0,
				Level:          "error",
				ErrorCode:      "SNYK-CLI-0044",
				Cause:          err,
				Classification: "ACTIONABLE",
			}
		}

		err = ns.errHandler(err, req.Context())
	}

	return res, err
}
