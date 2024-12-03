package middleware

import (
	"context"
	"net/http"

	"github.com/snyk/error-catalog-golang-public/snyk"
)

type ResponseMiddleware struct {
	next       http.RoundTripper
	errHandler func(error, context.Context) error
}

func NewReponseMiddleware(roundTriper http.RoundTripper, errHandler func(error, context.Context) error) *ResponseMiddleware {
	return &ResponseMiddleware{
		next:       roundTriper,
		errHandler: errHandler,
	}
}

// ErrFromStatusCode matches the providede status code to an Error Catalog error. If no match is found, nil is returned.
func ErrFromStatusCode(code int) error {
	switch code {
	case http.StatusUnauthorized:
		return snyk.NewUnauthorisedError("Use `snyk auth` to authenticate.")
	case http.StatusBadRequest:
		return snyk.NewBadRequestError("The request cannot be processed.")
	case http.StatusInternalServerError:
		return snyk.NewServerError("Internal server error.")
	default:
		return nil
	}
}

func (rm ResponseMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := rm.next.RoundTrip(req)

	if err != nil {
		return res, err
	}

	err = ErrFromStatusCode(res.StatusCode)

	if rm.errHandler != nil {
		err = rm.errHandler(err, res.Request.Context())
	}

	// RoundTrip should return one or the other.
	if err != nil {
		res = nil
	}

	return res, err
}
