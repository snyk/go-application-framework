package localworkflows

import (
	"maps"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_InitAuth_offersStdinAsABooleanFlag(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())
	require.NoError(t, InitAuth(engine))

	entry, ok := engine.GetWorkflow(WORKFLOWID_AUTH)
	require.True(t, ok)
	flag := workflow.FlagsetFromConfigurationOptions(entry.GetConfigurationOptions()).Lookup(stdinFlag)
	require.NotNil(t, flag)
	assert.Equal(t, "bool", flag.Value.Type())
}

// pipeToStdin makes input the process's stdin, as `echo "$SECRET" | snyk auth` does.
func pipeToStdin(t *testing.T, input string) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	go func() {
		defer func() { _ = w.Close() }()
		if _, writeErr := w.WriteString(input); writeErr != nil {
			return
		}
	}()
	original := os.Stdin
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = original
		_ = r.Close()
	})
}

func Test_auth_stdin_patIsValidatedAndStored(t *testing.T) {
	env := newSecretArgumentEnv(t)
	require.NoError(t, InitWhoAmIWorkflow(env.engine))
	pat := "snyk_uat.12345678.abcdefg-hijklmnop.qrstuvwxyz-123456"
	env.server.RegisterPAT(pat)
	pipeToStdin(t, pat+"\n")

	err := env.authWith(t, map[string]string{stdinFlag: "true"})

	require.NoError(t, err)
	assert.Equal(t, pat, env.storedValues(t)[auth.CONFIG_KEY_TOKEN], "snyk config get api returns the PAT")
	assert.Equal(t, 0, env.server.TokenAttempts())
}

func Test_auth_stdin_failsBeforeAnyRequest(t *testing.T) {
	tests := map[string]struct {
		piped  string
		values map[string]string
		want   []string
	}{
		"secret also as argument": {
			piped:  "shared-secret-1",
			values: map[string]string{auth.PARAMETER_CLIENT_ID: "client-1", ConfigurationNewAuthenticationToken: "shared-secret-1"},
			want:   []string{"--" + stdinFlag, "argument"},
		},
		"secret also in --client-secret": {
			piped:  "shared-secret-1",
			values: map[string]string{auth.PARAMETER_CLIENT_ID: "client-1", auth.PARAMETER_CLIENT_SECRET: "shared-secret-1"},
			want:   []string{"--" + stdinFlag, "--" + auth.PARAMETER_CLIENT_SECRET},
		},
		"empty input": {
			piped:  "\n",
			values: map[string]string{auth.PARAMETER_CLIENT_ID: "client-1"},
			want:   []string{"stdin was empty"},
		},
		"input over 64 KiB": {
			piped:  strings.Repeat("a", 64*1024+1),
			values: map[string]string{auth.PARAMETER_CLIENT_ID: "client-1"},
			want:   []string{"too large"},
		},
		"API token": {
			piped: "00000000-0000-0000-0000-000000000000",
			want:  []string{"token authentication doesn't read stdin"},
		},
		"auth type token": {
			piped:  "shared-secret-1",
			values: map[string]string{auth.PARAMETER_CLIENT_ID: "client-1", AuthTypeParameter: auth.AUTH_TYPE_TOKEN},
			want:   []string{"token authentication doesn't read stdin"},
		},
		"IDE detected": {
			piped:  "shared-secret-1",
			values: map[string]string{auth.PARAMETER_CLIENT_ID: "client-1", configuration.INTEGRATION_NAME: "VS_CODE"},
			want:   []string{"token authentication doesn't read stdin"},
		},
		"not a PAT without --client-id": {
			piped: "shared-secret-1",
			want:  []string{"not a PAT", "--" + auth.PARAMETER_CLIENT_ID},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newSecretArgumentEnv(t)
			holdBrowserLoginPorts(t)
			env.server.RegisterClientSecret("client-1", "shared-secret-1")
			pipeToStdin(t, tc.piped)
			values := map[string]string{stdinFlag: "true"}
			maps.Copy(values, tc.values)

			err := env.authWith(t, values)

			require.Error(t, err)
			for _, want := range tc.want {
				assert.ErrorContains(t, err, want)
			}
			assert.Equal(t, 0, env.server.TokenAttempts())
			assert.Empty(t, env.server.CredentialHeaders(), "no request carried a credential")
		})
	}
}

func Test_auth_stdin_sharedSecretIsNotStored(t *testing.T) {
	env := newSecretArgumentEnv(t)
	env.server.RegisterClientSecret("client-1", "shared-secret-1")
	pipeToStdin(t, "shared-secret-1\n")

	err := env.authWith(t, map[string]string{auth.PARAMETER_CLIENT_ID: "client-1", stdinFlag: "true"})

	require.NoError(t, err)
	for _, file := range filesUnder(t, env.home) {
		content, readErr := os.ReadFile(file)
		require.NoError(t, readErr)
		assert.NotContains(t, string(content), "shared-secret-1", file)
	}
}
