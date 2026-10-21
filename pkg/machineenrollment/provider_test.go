package machineenrollment_test

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/snyk/go-application-framework/pkg/machineenrollment"
	"github.com/snyk/go-application-framework/pkg/machineenrollment/enrollmenttest"
)

func TestAssertionProviderClientAssertion(t *testing.T) {
	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	keyFile := filepath.Join(t.TempDir(), "key.pem")
	require.NoError(t, machineenrollment.WriteKeyFile(keyFile, key))

	provider := machineenrollment.NewAssertionProvider(keyFile)

	assertionType, assertion, err := provider.ClientAssertion(context.Background(), "client-1", "https://api.example.com/oauth2/token")
	require.NoError(t, err)
	assert.Equal(t, machineenrollment.ClientAssertionType, assertionType)
	require.NoError(t, enrollmenttest.VerifyJWT(assertion, &key.PublicKey))

	_, claims := enrollmenttest.DecodeJWT(t, assertion)
	assert.Equal(t, "client-1", claims["iss"])
}

// TestAssertionProviderTokenExchange exercises the full private_key_jwt flow end to end against the
// enrollment test double's token endpoint: enroll to obtain a machine client key, then use
// NewAssertionProvider to fetch an access token via the OAuth2 client_credentials/clientcredentials
// package, the same way pkg/auth's assertion-based grant does internally.
func TestAssertionProviderTokenExchange(t *testing.T) {
	srv := enrollmenttest.NewServer(t)
	token := srv.IssueDeviceToken(srv.RegisterMachine())

	keyFile := filepath.Join(t.TempDir(), "key.pem")
	e, err := machineenrollment.EnrollWithDeviceToken(context.Background(), http.DefaultClient, srv.URL, token, time.Now())
	require.NoError(t, err)
	require.NoError(t, machineenrollment.WriteKeyFile(keyFile, e.Key))

	provider := machineenrollment.NewAssertionProvider(keyFile)
	tokenURL := srv.URL + "/oauth2/token"
	assertionType, assertion, err := provider.ClientAssertion(context.Background(), e.ClientID, tokenURL)
	require.NoError(t, err)

	conf := &clientcredentials.Config{
		ClientID: e.ClientID,
		TokenURL: tokenURL,
		EndpointParams: map[string][]string{
			"client_assertion_type": {assertionType},
			"client_assertion":      {assertion},
		},
	}
	tok, err := conf.Token(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, tok.AccessToken)
}
