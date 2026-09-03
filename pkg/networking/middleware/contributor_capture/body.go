package contributor_capture

import (
	"bytes"
	"compress/gzip"
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
// Deeproxy bodies arrive gzipped, so for that kind the peeked prefix is decoded
// before it is returned.
// fullyRead reports whether the body fit within maxBytes.
func peekResponseBody(res *http.Response, kind endpointKind, maxBytes int64) (peeked []byte, fullyRead bool, err error) {
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

	fullyRead = int64(len(buf)) <= maxBytes
	if !fullyRead {
		buf = buf[:maxBytes]
	}

	if kind == endpointDeeproxyReport {
		buf, err = gunzip(buf, fullyRead)
		if err != nil {
			return nil, false, err
		}
	}

	return buf, fullyRead, nil
}

// gunzip decodes a gzip stream. A truncated stream still yields everything that
// could be decoded.
func gunzip(buf []byte, complete bool) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	decoded, err := io.ReadAll(reader)
	if err != nil && complete {
		return nil, err
	}
	return decoded, nil
}

type stitchedReadCloser struct {
	io.Reader
	underlying io.ReadCloser
}

func (b *stitchedReadCloser) Close() error {
	return b.underlying.Close()
}
