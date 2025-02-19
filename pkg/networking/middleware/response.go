package middleware

import (
	"errors"
	"net/http"

	"github.com/snyk/error-catalog-golang-public/snyk"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/snyk/go-application-framework/pkg/configuration"
	networktypes "github.com/snyk/go-application-framework/pkg/networking/network_types"
)

type ResponseMiddleware struct {
	next       http.RoundTripper
	config     configuration.Configuration
	errHandler networktypes.ErrorHandlerFunc
}

func NewReponseMiddleware(roundTriper http.RoundTripper, config configuration.Configuration, errHandler networktypes.ErrorHandlerFunc) *ResponseMiddleware {
	return &ResponseMiddleware{
		next:       roundTriper,
		config:     config,
		errHandler: errHandler,
	}
}

func (rm ResponseMiddleware) RoundTrip(req *http.Request) (*http.Response, error) {
	res, err := rm.next.RoundTrip(req)

	if err != nil {
		return res, err
	}

	err = HandleResponse(res, rm.config)

	err = rm.errHandler(err, res.Request.Context())

	// RoundTrip should return one or the other.
	if err != nil {
		res = nil
	}

	return res, err
}

// HandleResponse maps the response param to the eror catalog error.
func HandleResponse(res *http.Response, config configuration.Configuration) error {
	if res == nil {
		return nil
	}

	apiUrl := config.GetString(configuration.API_URL)
	additionalSubdomains := config.GetStringSlice(configuration.AUTHENTICATION_SUBDOMAINS)
	additionalUrls := config.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS)

	isKnownHost, err := ShouldRequireAuthentication(apiUrl, res.Request.URL, additionalSubdomains, additionalUrls)

	// only handle request to known hosts
	//nolint:nilerr // this type of error is not surfaced to the user
	if !isKnownHost || err != nil {
		return nil
	}

	err = errFromStatusCode(res.StatusCode)
	if err != nil {
		return addRequestDataToErr(err, res)
	}

	return nil
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

// addRequestDataToErr adds the request-id and request-url fields in the metadata map for the error.
func addRequestDataToErr(err error, res *http.Response) error {
	reqId := res.Request.Header.Get("snyk-request-id")
	reqPath := res.Request.URL.Path

	return AddMetaDataToErr(err, map[string]any{
		"request-id":   reqId,
		"request-path": reqPath,
	})
}

// AddMetaDataToErr adds the provided metadata to the Error catalog error's metadata map.
func AddMetaDataToErr(err error, meta map[string]any) error {
	snykErr := snyk_errors.Error{}
	if !errors.As(err, &snykErr) {
		return err
	}

	if snykErr.Meta == nil {
		snykErr.Meta = make(map[string]any)
	}

	for k, v := range meta {
		snykErr.Meta[k] = v
	}

	return snykErr
}
