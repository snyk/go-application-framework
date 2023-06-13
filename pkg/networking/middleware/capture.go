package middleware

import "net/http"

// HeaderCapture A middleware that captures the headers of the request and doesn't send it
type HeaderCapture struct {
	CapturedHeaders map[string]string
}

func (h *HeaderCapture) RoundTrip(request *http.Request) (*http.Response, error) {
	h.CapturedHeaders = make(map[string]string)
	for k, v := range request.Header {
		h.CapturedHeaders[k] = v[0]
	}
	return nil, nil
}
