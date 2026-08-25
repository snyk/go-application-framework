package contributor_capture

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxCaptureBodyBytes bounds bodies read for contributor capture parsing.
const maxCaptureBodyBytes = 64 << 10 // 64 KiB

// errBodyTooLarge is returned when a body exceeds maxCaptureBodyBytes.
var errBodyTooLarge = errors.New("contributor capture: body exceeds capture limit")

// readRequestBodyForParse peeks a request body for capture parsing. When the
// on oversized bodies instead of an error, for callers that can parse from a prefix.
func readRequestBodyForParse(req *http.Request, maxBytes int64) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}

	limit := maxBytes + 1
	buf, readErr := io.ReadAll(io.LimitReader(req.Body, limit))
	if readErr != nil {
		req.Body = stitch(buf, req.Body)
		return nil, readErr
	}

	if int64(len(buf)) <= maxBytes {
		req.Body = io.NopCloser(bytes.NewReader(buf))
		return buf, nil
	}

	// Oversized body: return truncated prefix for parsing.
	req.Body = stitch(buf, req.Body)
	return buf[:maxBytes], nil
}

// readResponseBody peeks up to maxBytes of res.Body for parsing, restoring
// res.Body so it can still be read normally afterwards regardless of outcome.
func readResponseBody(res *http.Response, maxBytes int64) ([]byte, error) {
	if res.Body == nil {
		return nil, nil
	}
	peeked, restored, err := peekAndRestoreBody(res.Body, maxBytes)
	res.Body = restored
	return peeked, err
}

// readResponseBodyForParse peeks a response body for capture parsing. When the
// body exceeds maxBytes it returns a prefix with fullyRead=false and no error so
// callers that can parse billing fields from a prefix (deeproxy) may continue.
func readResponseBodyForParse(res *http.Response, maxBytes int64) (bodyBytes []byte, fullyRead bool, err error) {
	if res.Body == nil {
		return nil, false, nil
	}

	limit := maxBytes + 1
	buf, readErr := io.ReadAll(io.LimitReader(res.Body, limit))
	if readErr != nil {
		res.Body = stitch(buf, res.Body)
		return nil, false, readErr
	}

	if int64(len(buf)) <= maxBytes {
		_ = res.Body.Close()
		res.Body = seekableReadCloser{bytes.NewReader(buf)}
		return buf, true, nil
	}

	res.Body = stitch(buf, res.Body)
	return buf[:maxBytes], false, nil
}

func decodeCaptureBody(bodyBytes []byte, contentEncoding string) ([]byte, error) {
	if len(bodyBytes) == 0 {
		return bodyBytes, nil
	}

	switch strings.ToLower(strings.TrimSpace(contentEncoding)) {
	case "gzip", "x-gzip":
		reader, err := gzip.NewReader(bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		decoded, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		return decoded, nil
	default:
		return bodyBytes, nil
	}
}

func captureAllowsTruncatedBodyParse(kind EndpointKind) bool {
	return kind == EndpointDeeproxyReport
}

func peekAndRestoreBody(body io.ReadCloser, maxBytes int64) (peeked []byte, restored io.ReadCloser, err error) {
	limit := maxBytes + 1
	buf, readErr := io.ReadAll(io.LimitReader(body, limit))
	if readErr != nil {
		return nil, stitch(buf, body), readErr
	}

	if int64(len(buf)) <= maxBytes {
		_ = body.Close()
		return buf, seekableReadCloser{bytes.NewReader(buf)}, nil
	}

	return nil, stitch(buf, body), fmt.Errorf("%w (%d bytes)", errBodyTooLarge, maxBytes)
}

func stitch(buf []byte, body io.ReadCloser) io.ReadCloser {
	return &stitchedReadCloser{
		Reader:     io.MultiReader(bytes.NewReader(buf), body),
		underlying: body,
	}
}

type seekableReadCloser struct {
	*bytes.Reader
}

func (seekableReadCloser) Close() error { return nil }

type stitchedReadCloser struct {
	io.Reader
	underlying io.ReadCloser
}

func (b *stitchedReadCloser) Close() error {
	return b.underlying.Close()
}
