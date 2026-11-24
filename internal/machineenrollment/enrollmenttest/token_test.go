package enrollmenttest_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/internal/machineenrollment/enrollmenttest"
)

// signRS256 returns a compact JWS with the given header, signed with RS256 whatever the header claims.
func signRS256(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	headerJSON, err := json.Marshal(header)
	require.NoError(t, err)
	claimsJSON, err := json.Marshal(claims)
	require.NoError(t, err)
	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func postAssertion(t *testing.T, srv *enrollmenttest.Server, clientID, assertion string) int {
	t.Helper()
	resp, err := http.PostForm(srv.URL+"/oauth2/token", url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {machineenrollment.ClientAssertionType},
		"client_assertion":      {assertion},
		"client_id":             {clientID},
	})
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestTokenEndpointChecksTheAssertionHeader(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	e := enrolled(t, srv)

	for name, tt := range map[string]struct {
		header map[string]any
		want   int
	}{
		"RS256 with the key's kid": {header: map[string]any{"alg": "RS256", "typ": "JWT", "kid": e.KeyID}, want: http.StatusOK},
		"alg none":                 {header: map[string]any{"alg": "none", "typ": "JWT", "kid": e.KeyID}, want: http.StatusBadRequest},
		"alg HS256":                {header: map[string]any{"alg": "HS256", "typ": "JWT", "kid": e.KeyID}, want: http.StatusBadRequest},
		"alg RS512":                {header: map[string]any{"alg": "RS512", "typ": "JWT", "kid": e.KeyID}, want: http.StatusBadRequest},
		"wrong kid":                {header: map[string]any{"alg": "RS256", "typ": "JWT", "kid": "another-key"}, want: http.StatusBadRequest},
		"no kid":                   {header: map[string]any{"alg": "RS256", "typ": "JWT"}, want: http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			claims := map[string]any{
				"iss": e.ClientID, "sub": e.ClientID, "aud": srv.URL + "/oauth2/token",
				"jti": name + time.Now().String(), "exp": time.Now().Add(time.Minute).Unix(),
			}
			assert.Equal(t, tt.want, postAssertion(t, srv, e.ClientID, signRS256(t, e.Key, tt.header, claims)))
		})
	}
}
