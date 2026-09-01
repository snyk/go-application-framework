package contributor_capture

import (
	"bytes"
	"io"
	"net/http"
)

// maxCaptureBodyBytes bounds bodies read for contributor capture parsing.
const maxCaptureBodyBytes = 64 << 10 // 64 KiB

// peekRequestBody returns an independent copy of req's body, bounded to maxBytes.
// It reads through req.GetBody rather than req.Body, so the outgoing request is
// never touched. Bodies without a GetBody (streaming readers) are not captured.
func peekRequestBody(req *http.Request, maxBytes int64) ([]byte, error) {
	if req.GetBody == nil {
		return nil, nil
	}

	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	defer body.Close()

	return io.ReadAll(io.LimitReader(body, maxBytes))
}

// peekResponseBody returns up to maxBytes of res.Body for parsing and splices what
// it read back in front of the remainder, so res.Body still yields the whole body.
// fullyRead reports whether the body fit within maxBytes.
func peekResponseBody(res *http.Response, maxBytes int64) (peeked []byte, fullyRead bool, err error) {
	if res.Body == nil {
		return nil, false, nil
	}

	buf, err := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	res.Body = &stitchedReadCloser{
		Reader:     io.MultiReader(bytes.NewReader(buf), res.Body),
		underlying: res.Body,
	}
	if err != nil {
		return nil, false, err
	}

	if int64(len(buf)) > maxBytes {
		return buf[:maxBytes], false, nil
	}
	return buf, true, nil
}

type stitchedReadCloser struct {
	io.Reader
	underlying io.ReadCloser
}

func (b *stitchedReadCloser) Close() error {
	return b.underlying.Close()
}
