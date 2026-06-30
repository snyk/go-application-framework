package middleware

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

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
		return addResponseDataToErr(err, res)
	}

	return nil
}

func getErrorList(res *http.Response) []snyk_errors.Error {
	if res.Body == nil {
		return []snyk_errors.Error{}
	}
	originalBody := res.Body
	defer originalBody.Close()
	// get JSONApiErrors from body
	bodyBytes, err := io.ReadAll(res.Body)
	res.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	if err != nil {
		return []snyk_errors.Error{}
	}

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
	defaultError := errFromResponse(res)

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

// errFromResponse maps the response to an Error Catalog error, enriching it
// with response-specific data (e.g. rate-limit headers for 429s).
func errFromResponse(res *http.Response) error {
	baseErr := errFromStatusCode(res.StatusCode)
	if baseErr == nil {
		return nil
	}

	if res.StatusCode == http.StatusTooManyRequests {
		return enrichRateLimitError(baseErr, res)
	}

	return baseErr
}

// errFromStatusCode matches the status code to an Error Catalog error.
// If no match is found, nil is returned.
func errFromStatusCode(code int) error {
	switch code {
	case http.StatusUnauthorized:
		return snyk.NewUnauthorisedError("Use `snyk auth` to authenticate.")
	case http.StatusBadRequest:
		return snyk.NewBadRequestError("The request cannot be processed.")
	case http.StatusInternalServerError:
		return snyk.NewServerError("Internal server error.")
	case http.StatusTooManyRequests:
		err := snyk.NewTooManyRequestsError("")
		err.Level = "error"
		return err
	default:
		return nil
	}
}

// enrichRateLimitError adds rate-limit header data to a 429 error so the user
// sees a concrete retry-after duration and actionable guidance.
func enrichRateLimitError(err error, res *http.Response) error {
	var snykErr snyk_errors.Error
	if !errors.As(err, &snykErr) {
		return err
	}

	// always replace the generic description with actionable guidance
	snykErr.Description = "This limit is shared across all usage of this token \u2014 " +
		"parallel scans in CI or running different applications can exhaust it quickly. " +
		"Reduce the chance of this: lower scan concurrency in your pipeline, " +
		"add backoff/jitter between scans."

	const maxDisplayRetryAfter = 48 * time.Hour

	retryDelay := rateLimitRetryDelay(res)
	if retryDelay > 0 && retryDelay <= maxDisplayRetryAfter {
		retryTime := time.Now().Add(retryDelay)

		snykErr.Detail = fmt.Sprintf("Retry after: %s (\u2248%s).", utils.HumanDuration(retryDelay), retryTime.Format("15:04 MST"))
		snyk_errors.WithMeta("retry-after-seconds", int(retryDelay.Seconds()))(&snykErr)
	}

	return snykErr
}

// addRequestDataToErr adds the request-id and request-url fields in the metadata map for the error.
func addRequestDataToErr(err error, req *http.Request) error {
	if req == nil {
		return err
	}

	reqId := req.Header.Get("snyk-request-id")
	reqPath := req.URL.Path

	return utils.AddMetaDataToErr(err, map[string]any{
		"request-id":   reqId,
		"request-path": reqPath,
	})
}

// addRequestDataToErr adds the request-id and request-url fields in the metadata map for the error.
func addResponseDataToErr(err error, res *http.Response) error {
	return addRequestDataToErr(err, res.Request)
}
