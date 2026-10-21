package machineenrollment_test

import (
	"context"
	"net/http"
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
	assert.Equal(t, "ES256", header["alg"])
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
	assert.True(t, srv.ClientKey(e.ClientID).Equal(&e.Key.PublicKey), "the client is bound to the returned key")

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
