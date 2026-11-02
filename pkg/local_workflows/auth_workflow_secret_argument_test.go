package localworkflows

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/logging"
)

// authWith invokes the auth workflow with values set as the Snyk CLI sets flags and, for the
// positional argument, ConfigurationNewAuthenticationToken.
func (e *enrollEnv) authWith(t *testing.T, values map[string]string) error {
	t.Helper()
	invokeConfig := e.config.Clone()
	for key, value := range values {
		invokeConfig.Set(key, value)
	}
	_, err := e.engine.InvokeWithConfig(WORKFLOWID_AUTH, invokeConfig)
	return err
}

// newSecretArgumentEnv is newPrivateKeyAuthEnv where a browser login cannot open a browser.
func newSecretArgumentEnv(t *testing.T) *enrollEnv {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
	return newPrivateKeyAuthEnv(t)
}

func Test_auth_secretArgument_logsInLikeClientSecret(t *testing.T) {
	secrets := map[string]func(t *testing.T, env *enrollEnv) string{
		"shared secret": func(t *testing.T, env *enrollEnv) string {
			t.Helper()
			env.server.RegisterClientSecret("client-1", "shared-secret-1")
			return "shared-secret-1"
		},
		"private key": func(t *testing.T, env *enrollEnv) string {
			t.Helper()
			return issueClientKey(t, env.server, "client-1")
		},
	}
	sources := map[string]func(t *testing.T, secret string) (key, value string){
		"argument": func(_ *testing.T, secret string) (string, string) {
			return ConfigurationNewAuthenticationToken, secret
		},
		"--" + auth.PARAMETER_CLIENT_SECRET: func(_ *testing.T, secret string) (string, string) {
			return auth.PARAMETER_CLIENT_SECRET, secret
		},
		"--" + stdinFlag: func(t *testing.T, secret string) (string, string) {
			t.Helper()
			pipeToStdin(t, secret+"\n")
			return stdinFlag, "true"
		},
	}
	for secretName, secretFor := range secrets {
		for sourceName, source := range sources {
			t.Run(secretName+" in "+sourceName, func(t *testing.T) {
				env := newSecretArgumentEnv(t)
				logs := &bytes.Buffer{}
				logger := zerolog.New(logs).Level(zerolog.TraceLevel)
				env.engine.SetLogger(&logger)
				secret := secretFor(t, env)
				key, value := source(t, secret)

				err := env.authWith(t, map[string]string{auth.PARAMETER_CLIENT_ID: "client-1", key: value})

				require.NoError(t, err)
				assert.Equal(t, 1, env.server.TokenRequests)
				assert.Equal(t, http.StatusOK, env.whoamiInNewProcess(t), "a later process authenticates with the stored login")
				for _, line := range strings.Split(secret, "\n") {
					if len(line) >= 12 && !strings.HasPrefix(line, "-----") {
						assert.NotContains(t, logs.String(), line, "the secret is not logged")
					}
				}
			})
		}
	}
}

func Test_auth_secretArgument_withClientIDIsAClientSecretWhateverItLooksLike(t *testing.T) {
	secrets := map[string]string{
		"UUID-shaped": "00000000-0000-0000-0000-000000000000",
		"PAT-shaped":  "snyk_uat.12345678.abcdefg-hijklmnop.qrstuvwxyz-123456",
	}
	for name, secret := range secrets {
		t.Run(name, func(t *testing.T) {
			env := newSecretArgumentEnv(t)
			env.server.RegisterClientSecret("client-1", secret)

			err := env.authWith(t, map[string]string{auth.PARAMETER_CLIENT_ID: "client-1", ConfigurationNewAuthenticationToken: secret})

			require.NoError(t, err)
			assert.Equal(t, 1, env.server.TokenRequests, "the client credentials grant got a token")
		})
	}
}

func Test_auth_secretArgument_withClientSecretFailsBeforeAnyRequest(t *testing.T) {
	env := newSecretArgumentEnv(t)
	env.server.RegisterClientSecret("client-1", "shared-secret-1")

	err := env.authWith(t, map[string]string{
		auth.PARAMETER_CLIENT_ID:            "client-1",
		auth.PARAMETER_CLIENT_SECRET:        "shared-secret-1",
		ConfigurationNewAuthenticationToken: "shared-secret-1",
	})

	require.Error(t, err)
	assert.ErrorContains(t, err, "argument")
	assert.ErrorContains(t, err, "--"+auth.PARAMETER_CLIENT_SECRET)
	assert.Equal(t, 0, env.server.TokenAttempts())
}

// holdBrowserLoginPorts makes a browser login fail at once with "no available port". A port that
// another process holds blocks the login just as well.
func holdBrowserLoginPorts(t *testing.T) {
	t.Helper()
	for _, port := range []int{8080, 18081, 28082, 38083, 48084} {
		listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", auth.CALLBACK_HOSTNAME, port))
		if err == nil {
			t.Cleanup(func() { _ = listener.Close() })
		}
	}
}

func Test_auth_clientIDWithoutSecretStillStartsTheBrowserLogin(t *testing.T) {
	env := newSecretArgumentEnv(t)
	holdBrowserLoginPorts(t)

	err := env.authWith(t, map[string]string{auth.PARAMETER_CLIENT_ID: "client-1"})

	require.Error(t, err)
	assert.ErrorContains(t, err, "no available port", "the browser login was started")
	assert.Equal(t, 0, env.server.TokenAttempts())
}

func Test_auth_positionalArgumentOfAnotherCommandIsNoSecret(t *testing.T) {
	env := newSecretArgumentEnv(t)
	env.storeUserToken(t)
	// As the Snyk CLI does for `snyk test ./dir`.
	env.config.Set(ConfigurationNewAuthenticationToken, "./dir")

	res, err := env.engine.GetNetworkAccess().GetHttpClient().Get(env.server.URL + "/rest/whoami")
	require.NoError(t, err)
	_ = res.Body.Close()

	assert.Equal(t, []string{"user-access-token"}, env.server.BearerTokens(), "the request carries the stored login")
	assert.Equal(t, 0, env.server.TokenAttempts())
	logs := &bytes.Buffer{}
	_, err = logging.NewScrubbingIoWriter(logs, logging.GetScrubDictFromConfig(env.engine.GetConfiguration())).Write([]byte("scanning ./dir"))
	require.NoError(t, err)
	assert.Equal(t, "scanning ./dir", logs.String(), "the argument is not redacted as a secret")
}
