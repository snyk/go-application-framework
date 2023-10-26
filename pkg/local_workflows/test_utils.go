package localworkflows

import (
	"fmt"
	"net/http"
)

// roundTripFn
type roundTripFn func(req *http.Request) *http.Response
type roundTripErrorFn func(req *http.Request) *http.Response

func (f roundTripFn) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func (f roundTripErrorFn) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("yay, a test error")
}

// return *http.Client with Transport replaced to avoid making real calls
func newTestClient(fn roundTripFn) *http.Client {
	return &http.Client{
		Transport: fn,
	}
}

func newErrorProducingTestClient(fn roundTripErrorFn) *http.Client {
	return &http.Client{
		Transport: fn,
	}
}
