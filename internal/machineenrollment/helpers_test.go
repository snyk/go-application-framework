package machineenrollment_test

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/internal/machineenrollment/enrollmenttest"
)

// accessToken gets an access token for clientID from srv with a client assertion.
func accessToken(t *testing.T, srv *enrollmenttest.Server, key *rsa.PrivateKey, clientID string) string {
	t.Helper()
	assertion, err := machineenrollment.ClientAssertion(key, clientID, srv.URL+"/oauth2/token", time.Now())
	require.NoError(t, err)
	res, err := http.PostForm(srv.URL+"/oauth2/token", url.Values{
		"grant_type":            {"client_credentials"},
		"client_id":             {clientID},
		"client_assertion_type": {machineenrollment.ClientAssertionType},
		"client_assertion":      {assertion},
	})
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	require.Equal(t, http.StatusOK, res.StatusCode)
	var body struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.NewDecoder(res.Body).Decode(&body))
	return body.AccessToken
}

type bearer string

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b))
	return http.DefaultTransport.RoundTrip(r)
}
