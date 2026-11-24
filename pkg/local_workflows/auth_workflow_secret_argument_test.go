package localworkflows

import (
	"bytes"
	"fmt"
	"maps"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/logging"
)

// authWith invokes the auth workflow with values set as the host sets flags and, for the
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
func newSecretArgumentEnv(t *testing.T, opts ...configuration.Opts) *enrollEnv {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
	return newPrivateKeyAuthEnv(t, opts...)
}

// secretSources give the auth workflow a secret in each way a user can: the config value to set for it.
var secretSources = map[string]func(t *testing.T, env *enrollEnv, secret string) (key, value string){
	"argument": func(_ *testing.T, _ *enrollEnv, secret string) (string, string) {
		return ConfigurationNewAuthenticationToken, secret
	},
	"--" + auth.PARAMETER_CLIENT_SECRET: func(_ *testing.T, _ *enrollEnv, secret string) (string, string) {
		return auth.PARAMETER_CLIENT_SECRET, secret
	},
	"--" + stdinFlag: func(t *testing.T, env *enrollEnv, secret string) (string, string) {
		t.Helper()
		env.pipeToStdin(t, secret+"\n")
		return stdinFlag, "true"
	},
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
	for secretName, secretFor := range secrets {
		for sourceName, source := range secretSources {
			t.Run(secretName+" in "+sourceName, func(t *testing.T) {
				env := newSecretArgumentEnv(t)
				logs := &bytes.Buffer{}
				logger := zerolog.New(logs).Level(zerolog.TraceLevel)
				env.engine.SetLogger(&logger)
				secret := secretFor(t, env)
				key, value := source(t, env, secret)

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
		"PAT-shaped":  testPAT,
	}
	for secretName, secret := range secrets {
		for sourceName, source := range secretSources {
			t.Run(secretName+" in "+sourceName, func(t *testing.T) {
				env := newSecretArgumentEnv(t)
				env.server.RegisterClientSecret("client-1", secret)
				key, value := source(t, env, secret)

				err := env.authWith(t, map[string]string{auth.PARAMETER_CLIENT_ID: "client-1", key: value})

				require.NoError(t, err)
				assert.Equal(t, 1, env.server.TokenRequests, "the client credentials grant got a token")
			})
		}
	}
}

func Test_auth_secretReachesTheClientCredentialsGrantWhenTheHostCachedTheKeysBefore(t *testing.T) {
	for _, sourceName := range []string{"argument", "--" + stdinFlag} {
		t.Run(sourceName, func(t *testing.T) {
			env := newSecretArgumentEnv(t, configuration.WithCachingEnabled(configuration.NoCacheExpiration))
			env.server.RegisterClientSecret("client-1", "shared-secret-1")
			// The cache keeps only values that a default function returns.
			for _, cachedKey := range []string{auth.PARAMETER_CLIENT_SECRET, ConfigurationNewAuthenticationToken} {
				env.config.AddDefaultValue(cachedKey, configuration.StandardDefaultValueFunction(""))
				// As the Snyk CLI does at startup, for its redaction dictionary among others.
				assert.Empty(t, env.config.GetString(cachedKey))
			}
			key, value := secretSources[sourceName](t, env, "shared-secret-1")

			err := env.authWith(t, map[string]string{auth.PARAMETER_CLIENT_ID: "client-1", key: value})

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
	detail := invalidFlagDetail(t, err)
	assert.Contains(t, detail, "argument")
	assert.Contains(t, detail, "--"+auth.PARAMETER_CLIENT_SECRET)
	assert.Equal(t, 0, env.server.TokenAttempts())
}

func Test_auth_privateKeyErrorsNameWhereTheKeyWasGiven(t *testing.T) {
	tests := map[string]struct {
		source string
		values map[string]string
		want   string
	}{
		"unusable key in --stdin": {
			source: "--" + stdinFlag,
			values: map[string]string{auth.PARAMETER_CLIENT_ID: "client-1"},
			want:   "the --stdin input looks like a PEM private key",
		},
		"unusable key in the argument": {
			source: "argument",
			values: map[string]string{auth.PARAMETER_CLIENT_ID: "client-1"},
			want:   "the argument looks like a PEM private key",
		},
		"key in the argument without --client-id": {
			source: "argument",
			want:   "a private key in the argument needs --client-id",
		},
		"key in --stdin with auth type pat": {
			source: "--" + stdinFlag,
			values: map[string]string{auth.PARAMETER_CLIENT_ID: "client-1", AuthTypeParameter: auth.AUTH_TYPE_PAT},
			want:   "a private key in the --stdin input needs --auth-type=oauth",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newSecretArgumentEnv(t)
			key, value := secretSources[tc.source](t, env, pemOf(t, "PRIVATE KEY", []byte("not a key")))
			values := map[string]string{key: value}
			maps.Copy(values, tc.values)

			err := env.authWith(t, values)

			require.Error(t, err)
			assert.ErrorContains(t, err, tc.want)
			assert.NotContains(t, err.Error(), "--"+auth.PARAMETER_CLIENT_SECRET)
			assert.Equal(t, 0, env.server.TokenAttempts())
		})
	}
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
