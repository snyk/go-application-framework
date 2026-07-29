package llm

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseExtraHeaders(t *testing.T) {
	assert.Nil(t, parseExtraHeaders(""))
	assert.Nil(t, parseExtraHeaders("   "))
	assert.Nil(t, parseExtraHeaders("no-equals-sign"))

	h := parseExtraHeaders("x-user-id=jsmith, x-org-id = acme ")
	require.NotNil(t, h)
	assert.Equal(t, "jsmith", h.Get("x-user-id"))
	assert.Equal(t, "acme", h.Get("x-org-id"))

	// Pairs with an empty key are skipped.
	h = parseExtraHeaders("=novalue,ok=1")
	require.NotNil(t, h)
	assert.Empty(t, h.Get(""))
	assert.Equal(t, "1", h.Get("ok"))
}

// recordingTransport captures the request it receives so tests can assert what
// the composed transport did to the body/headers, then returns a canned 200.
type recordingTransport struct {
	gotBody   []byte
	gotHeader http.Header
}

func (rt *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		rt.gotBody, _ = io.ReadAll(req.Body)
	}
	rt.gotHeader = req.Header.Clone()
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(bytes.NewReader([]byte("{}"))),
		Header:     http.Header{},
	}, nil
}

// The temperature body-strip must still work when the base transport is a
// networking-style RoundTripper threaded in via WithNetworkAccess (i.e. the
// header transport composes over an arbitrary base, not just langchaingo's
// default). This guards the networking-integration composition (plan risk #2/#3).
func TestHeaderTransport_StripsTemperatureOverCustomBase(t *testing.T) {
	base := &recordingTransport{}
	ht := &headerTransport{
		base:      base,
		add:       http.Header{"x-user-id": {"jsmith"}},
		stripBody: strippedBodyFields,
	}

	body := bytes.NewReader([]byte(`{"model":"m","temperature":0,"messages":[]}`))
	req, err := http.NewRequest(http.MethodPost, "https://example.com/v1/messages", body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ht.RoundTrip(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.NotContains(t, string(base.gotBody), `"temperature"`, "temperature must be stripped over a custom base transport")
	assert.Contains(t, string(base.gotBody), `"model":"m"`, "other fields must be preserved")
	assert.Equal(t, "jsmith", base.gotHeader.Get("x-user-id"), "extra headers must reach the base transport")
}
