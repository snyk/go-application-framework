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
	"github.com/snyk/go-application-framework/pkg/utils"
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

	return res, err
}

// HandleResponse maps the response param to the error catalog error.
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

	err = getErrorsFromResponse(res)
	if err != nil {
		return addRequestDataToErr(err, res)
	}

	return nil
}

func getErrorList(res *http.Response) []snyk_errors.Error {
	// get JSONApiErrors from body
	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return []snyk_errors.Error{}
	}

	res.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	errorList, err := snyk_errors.FromJSONAPIErrorBytes(bodyBytes)
	if err != nil {
		return []snyk_errors.Error{}
	}

	return errorList
}

func getErrorsFromResponse(res *http.Response) error {
	if res.StatusCode >= http.StatusOK && res.StatusCode < http.StatusMultipleChoices {
		return nil
	}

	var resultError error
	defaultError := errFromStatusCode(res.StatusCode)

	// try to decode JSON API or Error Catalog Errors
	errorList := getErrorList(res)
	for _, actualError := range errorList {
		if len(actualError.Title) == 0 {
			continue
		}

		if ok, value := actualError.Meta["isErrorCatalogError"].(bool); !ok || !value { // JSON API Error
			var tmp snyk_errors.Error
			if ok = errors.As(defaultError, &tmp); !ok {
				tmp = cli.NewGeneralCLIFailureError("")
			}
			tmp.Detail = actualError.Detail
			tmp.StatusCode = actualError.StatusCode
			tmp.Title = actualError.Title
			actualError = tmp
		}
		resultError = errors.Join(resultError, actualError)
	}

	// default error handling from status code only
	if resultError == nil {
		resultError = defaultError
	}

	return resultError
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

	return utils.AddMetaDataToErr(err, map[string]any{
		"request-id":   reqId,
		"request-path": reqPath,
	})
}
