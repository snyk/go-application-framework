package networking

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

type fakeMachineSource struct {
	id   string
	cert *tls.Certificate
}

func (f *fakeMachineSource) MachineID() string                            { return f.id }
func (f *fakeMachineSource) ClientCertificate() (*tls.Certificate, error) { return f.cert, nil }
func (f *fakeMachineSource) SignProof(method, url string) (string, error) {
	return "proof " + method + " " + url, nil
}

func selfSignedCertificate(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "spiffe://snyk/machine/m-1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// newMutualTlsServer records, per request, whether a client certificate and a DPoP header arrived.
func newMutualTlsServer(t *testing.T, seen *[]string) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entry := "none"
		if len(r.TLS.PeerCertificates) > 0 {
			entry = "cert:" + r.TLS.PeerCertificates[0].Subject.CommonName
		}
		entry += " dpop:" + r.Header.Get(auth.DPOP_HEADER) + " authz:" + r.Header.Get("Authorization")
		*seen = append(*seen, entry)
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func Test_MachineIdentity_ConfiguredMode_PresentsCertificateAndProof(t *testing.T) {
	var seen []string
	server := newMutualTlsServer(t, &seen)

	config := getConfig()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.INSECURE_HTTPS, true)
	config.Set(configuration.IDENTITY_MODE, "machine")

	net := NewNetworkAccess(config)
	net.SetMachineIdentitySource(&fakeMachineSource{id: "m-1", cert: selfSignedCertificate(t)})

	rsp, err := net.GetHttpClient().Get(server.URL + "/self/heartbeat")
	require.NoError(t, err)
	defer rsp.Body.Close()

	require.Len(t, seen, 1)
	assert.Equal(t, "cert:spiffe://snyk/machine/m-1 dpop:proof GET "+server.URL+"/self/heartbeat authz:", seen[0])
}

func Test_MachineIdentity_PerCallSelection(t *testing.T) {
	var seen []string
	server := newMutualTlsServer(t, &seen)

	config := getConfig()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.INSECURE_HTTPS, true)
	config.Set(configuration.AUTHENTICATION_TOKEN, "user-token")

	net := NewNetworkAccess(config)
	net.SetMachineIdentitySource(&fakeMachineSource{id: "m-1", cert: selfSignedCertificate(t)})
	assert.NotNil(t, net.GetMachineIdentitySource())

	// default configuration is the user identity
	rsp, err := net.GetHttpClient().Get(server.URL + "/rest/self")
	require.NoError(t, err)
	rsp.Body.Close()

	// one call as the machine, the next one as the user again
	rsp, err = net.GetHttpClientForIdentity(auth.IdentityModeMachine).Get(server.URL + "/self/heartbeat")
	require.NoError(t, err)
	rsp.Body.Close()

	rsp, err = net.GetHttpClientForIdentity(auth.IdentityModeUser).Get(server.URL + "/rest/self")
	require.NoError(t, err)
	rsp.Body.Close()

	require.Len(t, seen, 3)
	assert.Equal(t, "none dpop: authz:token user-token", seen[0])
	assert.Equal(t, "cert:spiffe://snyk/machine/m-1 dpop:proof GET "+server.URL+"/self/heartbeat authz:", seen[1])
	assert.Equal(t, "none dpop: authz:token user-token", seen[2])
}

func Test_MachineIdentity_ModeWithoutSource_NeverSendsUserCredentials(t *testing.T) {
	var seen []string
	server := newMutualTlsServer(t, &seen)

	config := getConfig()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.INSECURE_HTTPS, true)
	config.Set(configuration.AUTHENTICATION_TOKEN, "user-token")
	config.Set(configuration.IDENTITY_MODE, "machine")

	net := NewNetworkAccess(config)
	assert.False(t, net.GetAuthenticator().IsSupported())
	assert.ErrorIs(t, net.GetAuthenticator().Authenticate(), auth.ErrMachineIdentityUnavailable)

	// the auth middleware keeps its existing policy of passing a request through when no header
	// can be produced, so the request goes out anonymously and the server decides
	rsp, err := net.GetHttpClient().Get(server.URL + "/rest/self")
	require.NoError(t, err)
	rsp.Body.Close()

	require.Len(t, seen, 1)
	assert.Equal(t, "none dpop: authz:", seen[0], "machine mode must not fall back to the user token")
}

func Test_MachineIdentity_CloneKeepsSource(t *testing.T) {
	net := NewNetworkAccess(getConfig())
	source := &fakeMachineSource{id: "m-1"}
	net.SetMachineIdentitySource(source)
	assert.Same(t, source, net.Clone().GetMachineIdentitySource())
}
