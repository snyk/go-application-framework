package contributor_capture

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/snyk/go-application-framework/internal/contributors"
)

// maxScanBytes bounds how much of a body is fed to an extractor. Bytes past it
// still reach the consumer, unscanned.
const maxScanBytes = 8 << 20 // 8 MiB

// maxDrainBytes bounds what closing a body reads from one the consumer
// abandoned. The streaming path scans up to the full budget, but a consumer
// that is not reading the body is not the case the budget exists for, so this
// keeps Close from reading a large body with no deadline of its own.
const maxDrainBytes = 64 << 10

// scanSettleTimeout bounds how long closing a body waits for its scan.
const scanSettleTimeout = 5 * time.Second

var (
	// errScanBudget is reported when a body outgrows maxScanBytes.
	errScanBudget = errors.New("scan budget exceeded")

	// errScanPanic is reported when an extractor panics.
	errScanPanic = errors.New("extractor panicked")

	// errUnexpectedToken is reported for a body of an unexpected shape.
	errUnexpectedToken = errors.New("unexpected json token")
)

// bodyExtractor pulls the entity ID a body carries out of its stream. It
// returns as soon as it has an answer, leaving the rest of the stream unread;
// an empty ID with a nil error means the body held no entity.
type bodyExtractor = func(r io.Reader) (string, error)

// scanResponseBody replaces res.Body with a reader that feeds extract as the
// consumer streams it, calling onResult once with whatever extract found. The
// consumer sees the whole body either way. onResult runs on another goroutine,
// but always before Close returns.
func scanResponseBody(res *http.Response, budget int64, extract bodyExtractor, onResult func(id string, err error)) {
	if res.Body == nil {
		onResult("", nil)
		return
	}

	pipeReader, pipeWriter := io.Pipe()
	done := make(chan struct{})

	go func() {
		defer close(done)

		id, err := runExtractor(extract, pipeReader)
		// Make any further feeding fail fast rather than block.
		_ = pipeReader.CloseWithError(io.EOF)
		onResult(id, err)
	}()

	res.Body = &scanningReadCloser{
		underlying: res.Body,
		writer:     pipeWriter,
		remaining:  budget,
		done:       done,
	}
}

// scanRequestBody runs extract over an independent copy of the request body, so
// the outgoing request is never touched. A body with no GetBody - a streaming
// reader - cannot be copied, so it is not scanned.
func scanRequestBody[T any](req *http.Request, budget int64, extract func(r io.Reader) (T, error)) (T, error) {
	var zero T
	if req.GetBody == nil {
		return zero, nil
	}

	body, err := req.GetBody()
	if err != nil {
		return zero, err
	}
	defer body.Close()

	return runExtractor(extract, &budgetReader{reader: body, remaining: budget})
}

// runExtractor contains a panicking extractor, so it cannot take down the
// request it was capturing from.
func runExtractor[T any](extract func(r io.Reader) (T, error), r io.Reader) (result T, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			var zero T
			result, err = zero, errScanPanic
		}
	}()

	return extract(r)
}

// scanningReadCloser feeds what the consumer reads to a scan running beside it.
type scanningReadCloser struct {
	underlying io.ReadCloser

	mu        sync.Mutex
	writer    *io.PipeWriter
	remaining int64

	done chan struct{}
}

func (s *scanningReadCloser) Read(p []byte) (int, error) {
	n, err := s.underlying.Read(p)
	if n > 0 {
		s.feed(p[:n])
	}
	if err != nil {
		s.stopFeeding(scanEndError(err))
	}
	return n, err
}

// Close finishes the scan and waits for its result, bounded by
// scanSettleTimeout, so capture is complete for every body a consumer closes
// whether or not it read one. Reaching the timeout means an extractor is
// wedged, and costs that capture rather than the consumer's Close.
func (s *scanningReadCloser) Close() error {
	s.drainForScan()
	s.stopFeeding(nil)
	err := s.underlying.Close()

	select {
	case <-s.done:
	case <-time.After(scanSettleTimeout):
	}

	return err
}

// drainForScan reads what the consumer left behind, so a body closed unread is
// still captured from. It stops once the scan answers, the scan budget is
// spent, or maxDrainBytes have been read, whichever comes first.
func (s *scanningReadCloser) drainForScan() {
	buf := make([]byte, 32<<10)
	allowance := int64(maxDrainBytes)

	for allowance > 0 && s.feeding() {
		chunk := buf
		if int64(len(chunk)) > allowance {
			chunk = chunk[:allowance]
		}

		n, err := s.underlying.Read(chunk)
		if n > 0 {
			s.feed(chunk[:n])
			allowance -= int64(n)
		}
		if err != nil {
			s.stopFeeding(scanEndError(err))
			return
		}
	}

	// Out of allowance with the body still going: the scan is missing the rest.
	s.stopFeeding(errScanBudget)
}

// scanEndError is what the scan should see when a body stops yielding bytes: a
// clean end for EOF, and the failure itself otherwise, so a body the consumer
// could not read is not reported as one that simply held no entity.
func scanEndError(err error) error {
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (s *scanningReadCloser) feeding() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writer != nil
}

// feed passes read bytes to the scan, up to the budget. A failed write means
// the scan has finished.
func (s *scanningReadCloser) feed(b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.writer == nil {
		return
	}

	// Bytes still arriving with no budget left: the scan is missing part of the
	// body. A body that ends exactly at the budget never reaches this, and ends
	// cleanly through Read's end-of-body path instead.
	if s.remaining == 0 {
		s.stop(errScanBudget)
		return
	}

	overBudget := int64(len(b)) > s.remaining
	if overBudget {
		b = b[:s.remaining]
	}

	if _, err := s.writer.Write(b); err != nil {
		s.stop(nil)
		return
	}
	s.remaining -= int64(len(b))

	if overBudget {
		s.stop(errScanBudget)
	}
}

func (s *scanningReadCloser) stopFeeding(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stop(err)
}

// stop ends the feeding half of the scan. A nil err lets the extractor see the
// end of the body; otherwise it sees err. Callers must hold s.mu.
func (s *scanningReadCloser) stop(err error) {
	if s.writer == nil {
		return
	}
	_ = s.writer.CloseWithError(err)
	s.writer = nil
}

// budgetReader stops the scan once a body has more than remaining bytes. A body
// ending exactly at the budget ends cleanly, since nothing was withheld.
type budgetReader struct {
	reader    io.Reader
	remaining int64
}

func (b *budgetReader) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		// One byte settles whether the body ran past the budget. Discarding it
		// is safe: this reads GetBody's own copy, not the outgoing request.
		if _, err := b.reader.Read(make([]byte, 1)); errors.Is(err, io.EOF) {
			return 0, io.EOF
		}
		return 0, errScanBudget
	}

	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}

	n, err := b.reader.Read(p)
	b.remaining -= int64(n)
	return n, err
}

// missReasonFor maps why a scan yielded no entity to the reason to report. A
// body that read fine but did not parse counts as holding no entity.
func missReasonFor(err error) contributors.MissReason {
	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError

	switch {
	case err == nil, errors.Is(err, io.EOF):
		return contributors.MissNoEntity
	case errors.Is(err, errScanBudget):
		return contributors.MissBodyTooLarge
	case errors.Is(err, errScanPanic):
		return contributors.MissPanic
	case errors.Is(err, errUnexpectedToken), errors.As(err, &syntaxErr), errors.As(err, &typeErr):
		return contributors.MissNoEntity
	default:
		return contributors.MissBodyUnreadable
	}
}
