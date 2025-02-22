package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	"github.com/snyk/error-catalog-golang-public/cli"
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

	err = errFromStatusCode(res)
	if err != nil {
		return addMetadataToErr(err, res)
	}

	return nil
}

// errFromStatusCode matches the providede status code to an Error Catalog error. If no match is found, nil is returned.
func errFromStatusCode(res *http.Response) error {
	if res.StatusCode >= http.StatusOK && res.StatusCode < http.StatusMultipleChoices {
		return nil
	}

	// get JSONApiErrors from body
	bodyBytes, err := io.ReadAll(res.Body)

	//nolint:nilerr // this type of error is not surfaced to the user
	if err != nil {
		return nil
	}
	res.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	errorList, err := snyk_errors.FromJSONAPIErrorBytes(bodyBytes)

	//nolint:nilerr // this type of error is not surfaced to the user
	if err != nil {
		return nil
	}

	if len(errorList) == 0 {
		return nil
	}

	// per error
	if ok, value := errorList[0].Meta["isErrorCatalogError"].(bool); ok && value {
		return errorList[0]
	}

	genericError := cli.NewGeneralCLIFailureError("")
	switch res.StatusCode {
	case http.StatusUnauthorized:
		genericError = snyk.NewUnauthorisedError("Use `snyk auth` to authenticate.")
	case http.StatusBadRequest:
		genericError = snyk.NewBadRequestError("The request cannot be processed.")
	case http.StatusInternalServerError:
		genericError = snyk.NewServerError("Internal server error.")
	default:
		genericError.StatusCode = errorList[0].StatusCode
		genericError.Title = errorList[0].Title
	}

	if len(genericError.Detail) > 0 && len(errorList[0].Detail) > 0 {
		genericError.Detail += "\n"
	}
	genericError.Detail += errorList[0].Detail

	return genericError
}

// addMetadataToErr adds the request-id and request-url fields in the metadata map for the error.
func addMetadataToErr(err error, res *http.Response) error {
	snykErr := snyk_errors.Error{}
	if !errors.As(err, &snykErr) {
		return err
	}

	if snykErr.Meta == nil {
		snykErr.Meta = make(map[string]any)
	}

	snykErr.Meta["request-id"] = res.Request.Header.Get("snyk-request-id")
	snykErr.Meta["request-path"] = res.Request.URL.Path

	return snykErr
}
