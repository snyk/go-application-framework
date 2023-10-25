package localworkflows

import "net/http"

// roundTripFn
type roundTripFn func(req *http.Request) *http.Response

// RoundTrip
func (f roundTripFn) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

// return *http.Client with Transport replaced to avoid making real calls
func newTestClient(fn roundTripFn) *http.Client {
	return &http.Client{
		Transport: roundTripFn(fn),
	}
}
