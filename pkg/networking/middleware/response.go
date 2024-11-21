package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
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

func errFromResponse(res *http.Response) error {
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		return nil
	}

	if err := errFromStatusCode(res.StatusCode); err != nil {
		return err
	}

	if err := errFromJSONAPI(res); err != nil {
		return err
	}

	return snyk_errors.Error{
		Title:       "Unsuccessful network request",
		Description: "A network request failed because with the resulting status code.",
		StatusCode:  res.StatusCode,
		Detail:      "Use the `-d` flag to inspect the request and response.",
		Level:       "error",
	}
}

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

func errFromJSONAPI(res *http.Response) error {
	snykErr := &jsonAPIErroResponse{}
	defer res.Body.Close()

	err := json.NewDecoder(res.Body).Decode(snykErr)
	if err != nil {
		return nil
	}

	return snykErr.ToErrorCatalog()
}

func (rm ResponseMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := rm.next.RoundTrip(req)

	if err != nil {
		return nil, err
	}

	err = errFromResponse(res)

	if rm.errHandler != nil {
		err = rm.errHandler(err, res.Request.Context())
	}

	// RoundTrip should return one or the other.
	if err != nil {
		res = nil
	}

	return res, err
}

type jsonAPIErroResponse struct {
	Errors []jsonAPIError `json:"errors"`
}

type jsonAPIError struct {
	Detail string `json:"detail,omitempty"`
	Status string `json:"status,omitempty"`
	Title  string `json:"title,omitempty"`
	Code   string `json:"code,omitempty"`
}

func (jar *jsonAPIErroResponse) ToErrorCatalog() error {
	if len(jar.Errors) == 0 {
		return nil
	}

	jsonErr := jar.Errors[0]
	fmt.Println(jsonErr)
	statusCode, err := strconv.Atoi(jsonErr.Status)
	if err != nil {
		statusCode = 0
	}

	return snyk_errors.Error{
		Title:      jsonErr.Title,
		Detail:     jsonErr.Detail,
		StatusCode: statusCode,
		ErrorCode:  jsonErr.Code,
	}
}
