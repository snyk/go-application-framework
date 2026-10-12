package machineenrollment_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/internal/machineenrollment/enrollmenttest"
)

func TestEnroll(t *testing.T) {
	ca := enrollmenttest.NewCA(t, "Device Management CA")
	other := enrollmenttest.NewCA(t, "Some Other CA")
	srv := enrollmenttest.NewServer(t, ca)
	identity := ca.Issue(t, "device-identity")
	keychain := &enrollmenttest.Keychain{
		Identities: []*enrollmenttest.Identity{other.Issue(t, "unrelated"), identity},
		Info:       machineenrollment.DeviceInfo{UDID: "udid-1", Serial: "serial-1"},
	}

	e, err := machineenrollment.Enroll(context.Background(), http.DefaultClient, srv.URL, keychain, time.Now())
	require.NoError(t, err)

	assert.Equal(t, "machine-1", e.MachineID)
	assert.Equal(t, "client-1", e.ClientID)
	assert.NotEmpty(t, e.KeyID)
	require.NotNil(t, e.Key)
	assert.True(t, srv.ClientKey(e.ClientID).Equal(&e.Key.PublicKey), "the client is bound to the returned key")
	assert.True(t, identity.Closed, "the identity is released")
	require.Len(t, srv.Attestations, 1)
	assert.Equal(t, "udid-1", srv.Attestations[0]["udid"])
	assert.Equal(t, "serial-1", srv.Attestations[0]["serial"])
}

func TestEnrollGeneratesANewKeyEachTime(t *testing.T) {
	ca := enrollmenttest.NewCA(t, "Device Management CA")
	srv := enrollmenttest.NewServer(t, ca)
	keychain := &enrollmenttest.Keychain{Identities: []*enrollmenttest.Identity{ca.Issue(t, "device-identity")}}

	first, err := machineenrollment.Enroll(context.Background(), http.DefaultClient, srv.URL, keychain, time.Now())
	require.NoError(t, err)
	second, err := machineenrollment.Enroll(context.Background(), http.DefaultClient, srv.URL, keychain, time.Now())
	require.NoError(t, err)

	assert.NotEqual(t, first.KeyID, second.KeyID)
}

func TestEnrollWithoutAnIdentityFromAnAcceptedIssuer(t *testing.T) {
	srv := enrollmenttest.NewServer(t, enrollmenttest.NewCA(t, "Device Management CA"))
	keychain := &enrollmenttest.Keychain{Identities: []*enrollmenttest.Identity{enrollmenttest.NewCA(t, "Other").Issue(t, "x")}}

	_, err := machineenrollment.Enroll(context.Background(), http.DefaultClient, srv.URL, keychain, time.Now())

	assert.ErrorIs(t, err, machineenrollment.ErrNoIdentity)
}

func TestEnrollReportsWhyTheServerRefused(t *testing.T) {
	ca := enrollmenttest.NewCA(t, "Device Management CA")
	srv := enrollmenttest.NewServer(t, ca)
	srv.RejectEnrollment = "This device is not in the fleet."
	keychain := &enrollmenttest.Keychain{Identities: []*enrollmenttest.Identity{ca.Issue(t, "device-identity")}}

	_, err := machineenrollment.Enroll(context.Background(), http.DefaultClient, srv.URL, keychain, time.Now())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
	assert.Contains(t, err.Error(), "This device is not in the fleet.")
}

func TestEnrollFailsWhenTheChallengeCannotBeFetched(t *testing.T) {
	ca := enrollmenttest.NewCA(t, "Device Management CA")
	srv := enrollmenttest.NewServer(t, ca)
	keychain := &enrollmenttest.Keychain{Identities: []*enrollmenttest.Identity{ca.Issue(t, "device-identity")}}

	_, err := machineenrollment.Enroll(context.Background(), http.DefaultClient, srv.URL+"/nowhere", keychain, time.Now())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "enrollment challenge")
}

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

func TestListTenants(t *testing.T) {
	ca := enrollmenttest.NewCA(t, "Device Management CA")
	srv := enrollmenttest.NewServer(t, ca)
	srv.Tenants = []machineenrollment.Tenant{{ID: "t-1", Name: "Tenant One"}}

	_, err := machineenrollment.ListTenants(context.Background(), http.DefaultClient, srv.URL)
	require.Error(t, err, "listing tenants needs authentication")
	assert.Contains(t, err.Error(), "401")

	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	srv.RegisterClient("client-1", &key.PublicKey)
	token := accessToken(t, srv, key, "client-1")
	client := &http.Client{Transport: bearer(token)}

	tenants, err := machineenrollment.ListTenants(context.Background(), client, srv.URL)
	require.NoError(t, err)
	assert.Equal(t, []machineenrollment.Tenant{{ID: "t-1", Name: "Tenant One"}}, tenants)
}
