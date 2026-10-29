package localworkflows

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/machinecredential"
	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/internal/machineenrollment/enrollmenttest"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/logging"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func newPrivateKeyAuthEnv(t *testing.T) *enrollEnv {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	server := enrollmenttest.NewServer(t)
	config := openFileBackedConfig()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)

	engine := workflow.NewWorkFlowEngine(config)
	require.NoError(t, InitAuth(engine))
	require.NoError(t, engine.Init())
	return &enrollEnv{home: home, server: server, engine: engine, config: config}
}

// issueClientKey registers a client with the fake service, as enrolling elsewhere does, and returns
// the PEM of its key.
func issueClientKey(t *testing.T, server *enrollmenttest.Server, clientID string) string {
	t.Helper()
	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	server.RegisterClient(clientID, &key.PublicKey)
	keyPEM, err := machineenrollment.EncodeKeyPEM(key)
	require.NoError(t, err)
	return string(keyPEM)
}

func (e *enrollEnv) authWithClientSecret(t *testing.T, clientID, secret string) error {
	t.Helper()
	invokeConfig := e.config.Clone()
	invokeConfig.Set(auth.PARAMETER_CLIENT_ID, clientID)
	invokeConfig.Set(auth.PARAMETER_CLIENT_SECRET, secret)
	_, err := e.engine.InvokeWithConfig(WORKFLOWID_AUTH, invokeConfig)
	return err
}

func Test_auth_privateKeySecret_laterProcessesUseTheStoredTokenThenTheStoredKey(t *testing.T) {
	env := newPrivateKeyAuthEnv(t)
	keyPEM := issueClientKey(t, env.server, "client-1")

	require.NoError(t, env.authWithClientSecret(t, "client-1", keyPEM))

	stored, err := machinecredential.Load(openFileBackedConfig())
	require.NoError(t, err)
	assert.Equal(t, "client-1", stored.ClientID)
	require.Equal(t, http.StatusOK, env.whoamiInNewProcess(t))
	assert.Equal(t, 1, env.server.TokenRequests, "the next process uses the token minted by the login")
	env.expireStoredAccessToken(t)
	assert.Equal(t, http.StatusOK, env.whoamiInNewProcess(t))
	assert.Equal(t, 2, env.server.TokenRequests, "a new token was minted from the stored key")
	assert.Equal(t, 0, env.server.EnrollmentRequests(), "logging in does not enroll")
}

// storeUserTokens stores the token of each kind of user login, with the alternative keys a host such
// as the Snyk CLI registers for the API token.
func (e *enrollEnv) storeUserTokens(t *testing.T) map[string]string {
	t.Helper()
	e.config.AddAlternativeKeys(configuration.AUTHENTICATION_TOKEN, []string{"snyk_cfg_api", auth.CONFIG_KEY_TOKEN})
	tokens := map[string]string{
		auth.CONFIG_KEY_OAUTH_TOKEN:        e.storeUserToken(t),
		configuration.AUTHENTICATION_TOKEN: "00000000-0000-0000-0000-000000000000",
		auth.CONFIG_KEY_TOKEN:              "snyk_uat.12345678.abcdefg-hijklmnop.qrstuvwxyz-123456",
	}
	for _, key := range []string{configuration.AUTHENTICATION_TOKEN, auth.CONFIG_KEY_TOKEN} {
		e.config.PersistInStorage(key)
		e.config.Set(key, tokens[key])
	}
	return tokens
}

func Test_auth_privateKeySecret_theServiceRejectsIsReportedAndKeepsTheExistingLogin(t *testing.T) {
	rejected := map[string]func(t *testing.T, env *enrollEnv) (string, string){
		"unknown client id": func(t *testing.T, env *enrollEnv) (string, string) {
			t.Helper()
			return "client-unknown", issueClientKey(t, env.server, "client-other")
		},
		"key of another client": func(t *testing.T, env *enrollEnv) (string, string) {
			t.Helper()
			issueClientKey(t, env.server, "client-a")
			return "client-a", issueClientKey(t, env.server, "client-b")
		},
	}
	for name, credentialFor := range rejected {
		t.Run(name+", user tokens kept", func(t *testing.T) {
			env := newPrivateKeyAuthEnv(t)
			userTokens := env.storeUserTokens(t)
			clientID, keyPEM := credentialFor(t, env)

			err := env.authWithClientSecret(t, clientID, keyPEM)

			require.Error(t, err)
			assert.ErrorContains(t, err, "failed authenticating as client "+clientID)
			assert.ErrorContains(t, err, "invalid_client", "the service's reason is kept")
			assertNothingStored(t, env.home)
			stored := env.storedValues(t)
			for key, token := range userTokens {
				assert.Equal(t, token, stored[key], key)
			}
		})
		t.Run(name+", stored key kept", func(t *testing.T) {
			env := newPrivateKeyAuthEnv(t)
			require.NoError(t, env.authWithClientSecret(t, "client-first", issueClientKey(t, env.server, "client-first")))
			clientID, keyPEM := credentialFor(t, env)

			err := env.authWithClientSecret(t, clientID, keyPEM)

			require.Error(t, err)
			stored, loadErr := machinecredential.Load(openFileBackedConfig())
			require.NoError(t, loadErr)
			assert.Equal(t, "client-first", stored.ClientID)
			assert.Equal(t, http.StatusOK, env.whoamiInNewProcess(t))
		})
	}
}

func Test_auth_privateKeySecret_replacesTheStoredUserTokensWithTheMintedToken(t *testing.T) {
	env := newPrivateKeyAuthEnv(t)
	userTokens := env.storeUserTokens(t)

	require.NoError(t, env.authWithClientSecret(t, "client-1", issueClientKey(t, env.server, "client-1")))

	stored := env.storedValues(t)
	for key := range userTokens {
		if key != auth.CONFIG_KEY_OAUTH_TOKEN {
			assert.NotContains(t, stored, key)
			assert.Empty(t, env.engine.GetConfiguration().GetString(key), "the engine's own configuration no longer holds %s", key)
		}
	}
	assert.Contains(t, stored, machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE)
	assert.NotEqual(t, userTokens[auth.CONFIG_KEY_OAUTH_TOKEN], env.engine.GetConfiguration().GetString(auth.CONFIG_KEY_OAUTH_TOKEN))
	minted, err := auth.GetOAuthToken(env.engine.GetConfiguration())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, env.whoamiInNewProcess(t))
	assert.Equal(t, []string{minted.AccessToken}, env.server.BearerTokens(), "the next process sends the token minted by the login")
}

func Test_auth_privateKeySecret_repeatLoginReplacesTheStoredKey(t *testing.T) {
	env := newPrivateKeyAuthEnv(t)
	require.NoError(t, env.authWithClientSecret(t, "client-first", issueClientKey(t, env.server, "client-first")))
	env.server.RevokeClient("client-first")

	require.NoError(t, env.authWithClientSecret(t, "client-second", issueClientKey(t, env.server, "client-second")))

	stored, err := machinecredential.Load(openFileBackedConfig())
	require.NoError(t, err)
	assert.Equal(t, "client-second", stored.ClientID)
	assert.Equal(t, http.StatusOK, env.whoamiInNewProcess(t))
}

func Test_auth_privateKeySecret_theEnginesOwnConfigurationSeesTheCredential(t *testing.T) {
	env := newPrivateKeyAuthEnv(t)

	require.NoError(t, env.authWithClientSecret(t, "client-1", issueClientKey(t, env.server, "client-1")))

	credential, err := machinecredential.Load(env.engine.GetConfiguration())
	require.NoError(t, err, "a host that authenticates in the same process sees the credential")
	assert.Equal(t, "client-1", credential.ClientID)
}

func Test_auth_privateKeySecret_unusableStorageFailsBeforeAnyNetworkCall(t *testing.T) {
	breakages := map[string]func(t *testing.T, env *enrollEnv){
		"no storage": func(t *testing.T, env *enrollEnv) {
			t.Helper()
			env.config.SetStorage(nil)
		},
		"storage that persists nothing": func(t *testing.T, env *enrollEnv) {
			t.Helper()
			env.config.SetStorage(&configuration.EmptyStorage{})
		},
		"configuration path is a directory": func(t *testing.T, env *enrollEnv) {
			t.Helper()
			require.NoError(t, os.MkdirAll(filepath.Join(env.configDir(), "snyk.json"), 0o755))
		},
	}
	for name, breakStorage := range breakages {
		t.Run(name, func(t *testing.T) {
			env := newPrivateKeyAuthEnv(t)
			keyPEM := issueClientKey(t, env.server, "client-1")
			breakStorage(t, env)

			err := env.authWithClientSecret(t, "client-1", keyPEM)

			require.Error(t, err)
			assert.ErrorContains(t, err, "cannot be stored")
			assert.Equal(t, 0, env.server.TokenRequests, "no token was minted")
		})
	}
}

func pemOf(t *testing.T, blockType string, der []byte) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}))
}

func Test_auth_privateKeySecret_unusableKeyFailsWithoutRevealingIt(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	sec1DER, err := x509.MarshalECPrivateKey(p256Key)
	require.NoError(t, err)
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p384DER, err := x509.MarshalPKCS8PrivateKey(p384Key)
	require.NoError(t, err)
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	require.NoError(t, err)
	corruptDER := slices.Clone(pkcs8DER)
	corruptDER[len(corruptDER)/2] ^= 0xff
	pkcs8PEM := pemOf(t, "PRIVATE KEY", pkcs8DER)

	keys := map[string]string{
		"PKCS1 RSA key":       pemOf(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey)),
		"SEC1 P-256 key":      pemOf(t, "EC PRIVATE KEY", sec1DER),
		"encrypted PKCS8":     pemOf(t, "ENCRYPTED PRIVATE KEY", pkcs8DER),
		"P-384 key":           pemOf(t, "PRIVATE KEY", p384DER),
		"corrupt PKCS8":       pemOf(t, "PRIVATE KEY", corruptDER),
		"truncated PKCS8":     pemOf(t, "PRIVATE KEY", pkcs8DER[:len(pkcs8DER)/2]),
		"public key block":    pemOf(t, "PUBLIC KEY", x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)),
		"escaped line breaks": strings.ReplaceAll(pkcs8PEM, "\n", `\n`),
	}
	for name, keyPEM := range keys {
		t.Run(name, func(t *testing.T) {
			env := newPrivateKeyAuthEnv(t)
			logs := &bytes.Buffer{}
			logger := zerolog.New(logs).Level(zerolog.TraceLevel)
			env.engine.SetLogger(&logger)

			err := env.authWithClientSecret(t, "client-1", keyPEM)

			require.Error(t, err)
			assert.ErrorContains(t, err, "openssl pkcs8 -topk8 -nocrypt")
			assert.Equal(t, 0, env.server.TokenRequests)
			assertNothingStored(t, env.home)
			for _, line := range strings.Split(strings.ReplaceAll(keyPEM, `\n`, "\n"), "\n") {
				if line = strings.TrimSpace(line); len(line) >= 16 && !strings.HasPrefix(line, "-----") {
					assert.NotContains(t, err.Error(), line)
					assert.NotContains(t, logs.String(), line)
				}
			}
		})
	}
}

func Test_auth_privateKeySecret_missingClientIDFailsAndStoresNothing(t *testing.T) {
	env := newPrivateKeyAuthEnv(t)
	keyPEM := issueClientKey(t, env.server, "client-1")

	err := env.authWithClientSecret(t, "", keyPEM)

	require.Error(t, err)
	assert.ErrorContains(t, err, "--"+auth.PARAMETER_CLIENT_ID)
	assert.Equal(t, 0, env.server.TokenRequests)
	assertNothingStored(t, env.home)
}

func Test_auth_privateKeySecret_logWritersCreatedBeforeTheLoginRedactTheKey(t *testing.T) {
	env := newPrivateKeyAuthEnv(t)
	logs := &bytes.Buffer{}
	// As the CLI does, before it parses the flags.
	writer := logging.NewScrubbingIoWriter(logs, logging.GetScrubDictFromConfig(env.config))
	keyPEM := issueClientKey(t, env.server, "client-1")

	require.NoError(t, env.authWithClientSecret(t, "client-1", keyPEM))

	pemBody := strings.Split(strings.TrimSpace(keyPEM), "\n")[1]
	for name, value := range map[string]string{
		"pem as is":           keyPEM,
		"one pem line":        pemBody,
		"escaped line breaks": strings.ReplaceAll(keyPEM, "\n", `\n`),
	} {
		logs.Reset()
		_, err := writer.Write([]byte("value: " + value))
		require.NoError(t, err)
		assert.NotContains(t, logs.String(), pemBody, name)
	}
}
