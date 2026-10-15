package machineenrollment_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/machineenrollment"
	"github.com/snyk/go-application-framework/pkg/machineenrollment/enrollmenttest"
)

func TestClientAssertion(t *testing.T) {
	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	now := time.Now()

	assertion, err := machineenrollment.ClientAssertion(key, "client-1", "https://api.example.com/oauth2/token", now)
	require.NoError(t, err)

	require.NoError(t, enrollmenttest.VerifyJWT(assertion, &key.PublicKey))
	header, claims := enrollmenttest.DecodeJWT(t, assertion)
	assert.Equal(t, "RS256", header["alg"])
	assert.NotEmpty(t, header["kid"])
	assert.Equal(t, "client-1", claims["iss"])
	assert.Equal(t, "client-1", claims["sub"])
	assert.Equal(t, "https://api.example.com/oauth2/token", claims["aud"])
	assert.NotEmpty(t, claims["jti"])
	assert.InDelta(t, now.Add(5*time.Minute).Unix(), claims["exp"], 1)
	assert.NotContains(t, claims, "iat", "iat is left out so clock skew can't get the assertion rejected")

	another, err := machineenrollment.ClientAssertion(key, "client-1", "https://api.example.com/oauth2/token", now)
	require.NoError(t, err)
	_, anotherClaims := enrollmenttest.DecodeJWT(t, another)
	assert.NotEqual(t, claims["jti"], anotherClaims["jti"])
}

func TestEnrollWithJoinToken(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	token := srv.IssueJoinToken()

	e, err := machineenrollment.EnrollWithJoinToken(context.Background(), http.DefaultClient, srv.URL, token, "", time.Now())
	require.NoError(t, err)

	assert.Equal(t, "machine-1", e.MachineID)
	assert.Equal(t, "client-1", e.ClientID)
	assert.NotEmpty(t, e.KeyID)
	require.NotNil(t, e.Key)
	assert.True(t, e.Key.PublicKey.Equal(srv.ClientKey(e.ClientID)), "the client is bound to the returned key")

	// A join key is single-use.
	_, err = machineenrollment.EnrollWithJoinToken(context.Background(), http.DefaultClient, srv.URL, token, "", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")
	assert.Contains(t, err.Error(), "The join key is not valid.")
}

func TestEnrollWithJoinTokenRejectsMalformedTokens(t *testing.T) {
	// Nothing listens here, so a request would fail with a different error.
	const apiURL = "http://127.0.0.1:1"
	for _, token := range []string{"", "sjt_", "not-a-join-key"} {
		_, err := machineenrollment.EnrollWithJoinToken(context.Background(), http.DefaultClient, apiURL, token, "", time.Now())
		assert.ErrorIs(t, err, machineenrollment.ErrMalformedJoinToken, token)
	}
}

func TestEnrollWithJoinTokenRequestBody(t *testing.T) {
	var gotPath, gotQuery, gotType string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery, gotType = r.URL.Path, r.URL.RawQuery, r.Header.Get("Content-Type")
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.WriteHeader(http.StatusCreated)
		_, werr := w.Write([]byte(`{"data":{"id":"c","type":"machine_enrollment","attributes":{"machine_id":"m","client_id":"c","key_id":"k"}}}`))
		assert.NoError(t, werr)
	}))
	defer srv.Close()

	e, err := machineenrollment.EnrollWithJoinToken(context.Background(), srv.Client(), srv.URL, "sjt_abc", "local-id", time.Now())
	require.NoError(t, err)
	assert.Equal(t, "m", e.MachineID)

	assert.Equal(t, "/hidden/machines/enrollments", gotPath)
	assert.Equal(t, "version=2024-10-15", gotQuery)
	assert.Equal(t, "application/vnd.api+json", gotType)

	// Exactly {"data":{"type":"machine_enrollment","attributes":{"assertion":"<jwt>"}}}.
	require.Len(t, gotBody, 1)
	data, ok := gotBody["data"].(map[string]any)
	require.True(t, ok)
	require.Len(t, data, 2)
	assert.Equal(t, "machine_enrollment", data["type"])
	attrs, ok := data["attributes"].(map[string]any)
	require.True(t, ok)
	require.Len(t, attrs, 1)
	assertion, ok := attrs["assertion"].(string)
	require.True(t, ok)
	assert.Len(t, strings.Split(assertion, "."), 3)
}

// roundTripFunc captures requests sent through an http.Client.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestEnrollWithJoinTokenSendsRS256AssertionWithRSAJWK(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	var body []byte
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		var err error
		if body, err = io.ReadAll(r.Body); err != nil {
			return nil, err
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		return http.DefaultTransport.RoundTrip(r)
	})}

	e, err := machineenrollment.EnrollWithJoinToken(context.Background(), client, srv.URL, srv.IssueJoinToken(), "", time.Now())
	require.NoError(t, err)

	var req struct {
		Data struct {
			Attributes struct {
				Assertion string `json:"assertion"`
			} `json:"attributes"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &req))
	header, claims := enrollmenttest.DecodeJWT(t, req.Data.Attributes.Assertion)
	assert.Equal(t, "RS256", header["alg"])
	jwk, ok := header["jwk"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "RSA", jwk["kty"])
	assert.NotEmpty(t, jwk["n"])
	assert.NotEmpty(t, jwk["e"])
	assert.NotContains(t, jwk, "d")
	assert.Contains(t, claims, "join_token")
	assert.Contains(t, claims, "aud")
	assert.Contains(t, claims, "iat")
	assert.GreaterOrEqual(t, e.Key.N.BitLen(), 2048)
}
