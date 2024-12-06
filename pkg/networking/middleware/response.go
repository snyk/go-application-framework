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

	if rm.errHandler != nil {
		err = rm.errHandler(err, res.Request.Context())
	}

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
	//nolint:errcheck // discarded error since it's returned only with the value of false
	requiresAuth, _ := ShouldRequireAuthentication(apiUrl, res.Request.URL, additionalSubdomains, additionalUrls)

	if !requiresAuth {
		return nil
	}

	err := errFromStatusCode(res.StatusCode)
	if err != nil {
		return addMetadataToErr(err, res)
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
