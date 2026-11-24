package enrollmenttest_test

import (
	"context"
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

func enrolled(t *testing.T, srv *enrollmenttest.Server) machineenrollment.Enrollment {
	t.Helper()
	e, err := machineenrollment.EnrollWithDeviceToken(context.Background(), http.DefaultClient, srv.URL, srv.IssueDeviceToken(srv.RegisterMachine()), time.Now())
	require.NoError(t, err)
	return e
}

func mintAccessToken(t *testing.T, srv *enrollmenttest.Server, e machineenrollment.Enrollment) string {
	t.Helper()
	tokenURL := srv.URL + "/oauth2/token"
	assertion, err := machineenrollment.ClientAssertion(e.Key, e.ClientID, tokenURL, time.Now())
	require.NoError(t, err)
	resp, err := http.PostForm(tokenURL, url.Values{
		"grant_type":            {"client_credentials"},
		"client_assertion_type": {machineenrollment.ClientAssertionType},
		"client_assertion":      {assertion},
		"client_id":             {e.ClientID},
	})
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var body struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	return body.AccessToken
}

func whoami(t *testing.T, srv *enrollmenttest.Server, authorization string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/rest/whoami", nil)
	require.NoError(t, err)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestWhoamiAcceptsOnlyTokensTheServerIssued(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	token := mintAccessToken(t, srv, enrolled(t, srv))

	assert.Equal(t, http.StatusUnauthorized, whoami(t, srv, ""))
	assert.Equal(t, http.StatusUnauthorized, whoami(t, srv, "Bearer token-unknown-1"))
	assert.Equal(t, http.StatusUnauthorized, whoami(t, srv, token))
	assert.Equal(t, http.StatusOK, whoami(t, srv, "Bearer "+token))
}

func TestEnrollmentRequestsCountsEachAttemptIncludingRejected(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	assert.Zero(t, srv.EnrollmentRequests())

	token := srv.IssueDeviceToken(srv.RegisterMachine())
	_, err := machineenrollment.EnrollWithDeviceToken(context.Background(), http.DefaultClient, srv.URL, token, time.Now())
	require.NoError(t, err)
	assert.Equal(t, 1, srv.EnrollmentRequests())

	_, err = machineenrollment.EnrollWithDeviceToken(context.Background(), http.DefaultClient, srv.URL, token, time.Now())
	require.Error(t, err)
	assert.Equal(t, 2, srv.EnrollmentRequests())
}
