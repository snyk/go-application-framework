package contributor_capture

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// maxCaptureBodyBytes bounds bodies read for contributor capture parsing.
const maxCaptureBodyBytes = 64 << 10 // 64 KiB

// errBodyTooLarge is returned when a body exceeds maxCaptureBodyBytes.
var errBodyTooLarge = errors.New("contributor capture: body exceeds capture limit")

// readRequestBody peeks up to maxBytes of req.Body for parsing, restoring
// req.Body so it can still be read normally afterwards regardless of outcome.
func readRequestBody(req *http.Request, maxBytes int64) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}
	peeked, restored, err := peekAndRestoreBody(req.Body, maxBytes)
	req.Body = restored
	return peeked, err
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
