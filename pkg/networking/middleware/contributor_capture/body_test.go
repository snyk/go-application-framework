package contributor_capture_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/contributors"
	cc "github.com/snyk/go-application-framework/pkg/networking/middleware/contributor_capture"
)

const testScanBudget = 1 << 20

// findMarker is a stand-in extractor returning what follows a marker, so a
// test can control where in a body the scan finds its answer.
func findMarker(marker string) func(io.Reader) (string, error) {
	return func(r io.Reader) (string, error) {
		body, err := io.ReadAll(r)
		idx := bytes.Index(body, []byte(marker))
		if idx < 0 {
			return "", err
		}
		rest := string(body[idx+len(marker):])
		if end := strings.IndexByte(rest, '\n'); end >= 0 {
			rest = rest[:end]
		}
		return rest, nil
	}
}

func TestScanResponseBody_passesTheWholeBodyToTheConsumer(t *testing.T) {
	t.Parallel()

	const body = "head\nid=found\ntail\n"
	res := &http.Response{Body: io.NopCloser(strings.NewReader(body))}

	var gotID string
	var gotErr error
	cc.ScanResponseBody(res, testScanBudget, findMarker("id="), func(id string, err error) {
		gotID, gotErr = id, err
	})

	read, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	assert.Equal(t, body, string(read), "the consumer must see the body unchanged")
	assert.Equal(t, "found", gotID)
	require.NoError(t, gotErr)
}

func TestScanResponseBody_resultIsRecordedByTheTimeTheBodyIsClosed(t *testing.T) {
	t.Parallel()

	res := &http.Response{Body: io.NopCloser(strings.NewReader("id=abc\n"))}

	recorded := make(chan string, 1)
	cc.ScanResponseBody(res, testScanBudget, findMarker("id="), func(id string, _ error) {
		recorded <- id
	})

	_, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	// No waiting here: Close is the point capture is guaranteed complete.
	select {
	case id := <-recorded:
		assert.Equal(t, "abc", id)
	default:
		t.Fatal("closing the body must not return before the scan result is in")
	}
}

func TestScanResponseBody_stopsFeedingOnceTheExtractorHasAnswered(t *testing.T) {
	t.Parallel()

	// The extractor answers at the first line, so the megabyte behind it never
	// reaches the scan.
	tail := strings.Repeat("x", 1<<20)
	body := "id=early\n" + tail
	res := &http.Response{Body: io.NopCloser(strings.NewReader(body))}

	var gotID string
	cc.ScanResponseBody(res, testScanBudget, func(r io.Reader) (string, error) {
		buf := make([]byte, len("id=early\n"))
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return strings.TrimSuffix(strings.TrimPrefix(string(buf), "id="), "\n"), nil
	}, func(id string, _ error) {
		gotID = id
	})

	read, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	assert.Equal(t, body, string(read))
	assert.Equal(t, "early", gotID)
}

func TestScanResponseBody_reportsBudgetExceededWithoutTruncatingTheConsumer(t *testing.T) {
	t.Parallel()

	const budget = 16
	body := strings.Repeat("y", 64) + "id=late\n"
	res := &http.Response{Body: io.NopCloser(strings.NewReader(body))}

	var gotErr error
	cc.ScanResponseBody(res, budget, findMarker("id="), func(_ string, err error) {
		gotErr = err
	})

	read, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	assert.Equal(t, body, string(read), "a body past the budget still reaches the consumer in full")
	require.ErrorIs(t, gotErr, cc.ErrScanBudget)
	assert.Equal(t, contributors.MissBodyTooLarge, cc.MissReasonFor(gotErr))
}

func TestScanResponseBody_endsCleanlyForABodyExactlyAtTheBudget(t *testing.T) {
	t.Parallel()

	const body = "no marker here"
	res := &http.Response{Body: io.NopCloser(strings.NewReader(body))}

	var gotErr error
	cc.ScanResponseBody(res, int64(len(body)), findMarker("id="), func(_ string, err error) {
		gotErr = err
	})

	read, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	assert.Equal(t, body, string(read))
	require.NoError(t, gotErr, "a body the scan saw in full must not report as too large")
	assert.Equal(t, contributors.MissNoEntity, cc.MissReasonFor(gotErr))
}

func TestScanResponseBody_drainsOnlyItsAllowanceFromAnAbandonedBody(t *testing.T) {
	t.Parallel()

	// Larger than the drain allowance, with nothing to find, so the drain runs
	// until its allowance is spent rather than to the end of the body.
	underlying := &trackedReadCloser{Reader: strings.NewReader(strings.Repeat("y", 4*cc.MaxDrainBytes))}
	res := &http.Response{Body: underlying}

	var gotErr error
	cc.ScanResponseBody(res, cc.MaxScanBytes, findMarker("id="), func(_ string, err error) {
		gotErr = err
	})

	require.NoError(t, res.Body.Close())

	assert.LessOrEqual(t, underlying.read, cc.MaxDrainBytes,
		"closing an abandoned body must not read it all looking for an entity")
	require.ErrorIs(t, gotErr, cc.ErrScanBudget)
}

func TestScanResponseBody_closesUnderlyingBodyAndSettlesWhenAbandoned(t *testing.T) {
	t.Parallel()

	underlying := &trackedReadCloser{Reader: strings.NewReader("id=never-read\n")}
	res := &http.Response{Body: underlying}

	results := make(chan error, 1)
	cc.ScanResponseBody(res, testScanBudget, findMarker("nothing-here"), func(_ string, err error) {
		results <- err
	})

	// A consumer that gives up without reading.
	require.NoError(t, res.Body.Close())

	assert.True(t, underlying.closed, "closing the wrapper must close the body it wraps")
	select {
	case err := <-results:
		require.NoError(t, err)
	default:
		t.Fatal("an abandoned body must still settle its scan")
	}
}

func TestScanResponseBody_surfacesReadErrorsToTheConsumer(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("read failed")
	underlying := &trackedReadCloser{Reader: strings.NewReader("id=part"), failAfterEOF: wantErr}
	res := &http.Response{Body: underlying}

	var gotID string
	cc.ScanResponseBody(res, testScanBudget, findMarker("id="), func(id string, _ error) {
		gotID = id
	})

	_, err := io.ReadAll(res.Body)
	require.ErrorIs(t, err, wantErr)
	require.NoError(t, res.Body.Close())

	assert.Equal(t, "part", gotID, "an ID already read stands, whatever happens to the rest of the body")
}

func TestScanResponseBody_reportsAFailedReadAsAnUnreadableBody(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("connection reset")
	underlying := &trackedReadCloser{Reader: strings.NewReader("no marker here"), failAfterEOF: wantErr}
	res := &http.Response{Body: underlying}

	var gotErr error
	cc.ScanResponseBody(res, testScanBudget, findMarker("id="), func(_ string, err error) {
		gotErr = err
	})

	_, err := io.ReadAll(res.Body)
	require.ErrorIs(t, err, wantErr)
	require.NoError(t, res.Body.Close())

	require.ErrorIs(t, gotErr, wantErr)
	assert.Equal(t, contributors.MissBodyUnreadable, cc.MissReasonFor(gotErr),
		"a body the consumer could not read must not report as one holding no entity")
}

func TestScanResponseBody_containsAPanickingExtractor(t *testing.T) {
	t.Parallel()

	const body = "id=abc\n"
	res := &http.Response{Body: io.NopCloser(strings.NewReader(body))}

	var gotErr error
	cc.ScanResponseBody(res, testScanBudget, func(io.Reader) (string, error) {
		panic("extractor exploded")
	}, func(_ string, err error) {
		gotErr = err
	})

	read, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())

	assert.Equal(t, body, string(read), "a panicking extractor must not cost the consumer its body")
	require.ErrorIs(t, gotErr, cc.ErrScanPanic)
	assert.Equal(t, contributors.MissPanic, cc.MissReasonFor(gotErr))
}

func TestScanRequestBody(t *testing.T) {
	t.Parallel()

	t.Run("reads a replayable body without consuming the request", func(t *testing.T) {
		t.Parallel()

		const body = "id=req\n"
		req, err := http.NewRequest(http.MethodPost, "https://api.snyk.io/rest/orgs/x/ai_boms/upload", strings.NewReader(body))
		require.NoError(t, err)

		id, err := cc.ScanRequestBody(req, testScanBudget, findMarker("id="))
		require.NoError(t, err)
		assert.Equal(t, "req", id)

		sent, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.Equal(t, body, string(sent), "the outgoing request must still carry its whole body")
	})

	t.Run("skips a body that cannot be replayed", func(t *testing.T) {
		t.Parallel()

		req, err := http.NewRequest(http.MethodPost, "https://api.snyk.io/v1/monitor", io.NopCloser(strings.NewReader("id=streamed\n")))
		require.NoError(t, err)
		req.GetBody = nil

		id, err := cc.ScanRequestBody(req, testScanBudget, findMarker("id="))
		require.NoError(t, err)
		assert.Empty(t, id, "a streaming body has no independent copy to scan")
	})

	t.Run("a body exactly at the budget ends cleanly", func(t *testing.T) {
		t.Parallel()

		const body = "no marker here"
		req, err := http.NewRequest(http.MethodPost, "https://api.snyk.io/v1/monitor", strings.NewReader(body))
		require.NoError(t, err)

		id, err := cc.ScanRequestBody(req, int64(len(body)), findMarker("id="))
		require.NoError(t, err, "a body the scan read in full must not report as too large")
		assert.Empty(t, id)
	})

	t.Run("reports budget exceeded", func(t *testing.T) {
		t.Parallel()

		req, err := http.NewRequest(http.MethodPost, "https://api.snyk.io/v1/monitor", strings.NewReader(strings.Repeat("z", 128)+"id=late\n"))
		require.NoError(t, err)

		_, err = cc.ScanRequestBody(req, 16, findMarker("id="))
		require.ErrorIs(t, err, cc.ErrScanBudget)
	})
}

func TestMissReasonFor(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		want contributors.MissReason
	}{
		"nothing found":     {err: nil, want: contributors.MissNoEntity},
		"empty body":        {err: io.EOF, want: contributors.MissNoEntity},
		"budget exceeded":   {err: cc.ErrScanBudget, want: contributors.MissBodyTooLarge},
		"extractor panic":   {err: cc.ErrScanPanic, want: contributors.MissPanic},
		"malformed json":    {err: mustSyntaxError(t), want: contributors.MissNoEntity},
		"truncated stream":  {err: io.ErrUnexpectedEOF, want: contributors.MissBodyUnreadable},
		"transport failure": {err: errors.New("connection reset"), want: contributors.MissBodyUnreadable},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, cc.MissReasonFor(tt.err))
		})
	}
}

// mustSyntaxError returns the error encoding/json reports for a malformed body.
func mustSyntaxError(t *testing.T) error {
	t.Helper()

	err := json.Unmarshal([]byte(`{invalid}`), &struct{}{})
	require.Error(t, err)
	return err
}

// trackedReadCloser records whether it was closed, and can fail once its
// content has been read, standing in for a connection that drops mid-body.
type trackedReadCloser struct {
	io.Reader
	closed       bool
	read         int
	failAfterEOF error
}

func (t *trackedReadCloser) Read(p []byte) (int, error) {
	n, err := t.Reader.Read(p)
	t.read += n
	if errors.Is(err, io.EOF) && t.failAfterEOF != nil {
		return n, t.failAfterEOF
	}
	return n, err
}

func (t *trackedReadCloser) Close() error {
	t.closed = true
	return nil
}
