package middleware

import (
	"net/http"

	"github.com/snyk/error-catalog-golang-public/snyk"
	networktypes "github.com/snyk/go-application-framework/pkg/networking/network_types"
)

type ResponseMiddleware struct {
	next       http.RoundTripper
	errHandler networktypes.ErrorHandlerFunc
}

func NewReponseMiddleware(roundTriper http.RoundTripper, errHandler networktypes.ErrorHandlerFunc) *ResponseMiddleware {
	return &ResponseMiddleware{
		next:       roundTriper,
		errHandler: errHandler,
	}
}

// errFromStatusCode matches the providede status code to an Error Catalog error. If no match is found, nil is returned.
func errFromStatusCode(code int) error {
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

// HandleResponse maps the response param to the eror catalog error.
func HandleResponse(res *http.Response) error {
	if err := errFromStatusCode(res.StatusCode); err != nil {
		return err
	}

	return nil
}

func (rm ResponseMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := rm.next.RoundTrip(req)

	if err != nil {
		return res, err
	}

	err = HandleResponse(res)

	if rm.errHandler != nil {
		err = rm.errHandler(err, res.Request.Context())
	}

	// RoundTrip should return one or the other.
	if err != nil {
		res = nil
	}

	return res, err
}
