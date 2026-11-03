package localworkflows

import (
	"errors"
	"io"
	"maps"
	"os"
	"strings"
	"testing"

	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
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

// pipeToStdin makes input what the auth workflow reads on stdin, as `echo "$SECRET" | snyk auth` does.
func (e *enrollEnv) pipeToStdin(t *testing.T, input string) {
	t.Helper()
	_, err := e.stdin.WriteString(input)
	require.NoError(t, err)
	_, err = e.stdin.Seek(0, io.SeekStart)
	require.NoError(t, err)
}

// invalidFlagDetail returns the detail of err, which must be the error catalog's invalid flag option error.
func invalidFlagDetail(t *testing.T, err error) string {
	t.Helper()
	var catalogErr snyk_errors.Error
	require.True(t, errors.As(err, &catalogErr), "error catalog error: %v", err)
	assert.Equal(t, cli.NewInvalidFlagOptionError("").ErrorCode, catalogErr.ErrorCode)
	return catalogErr.Detail
}

const testPAT = "snyk_uat.12345678.abcdefg-hijklmnop.qrstuvwxyz-123456"

func Test_auth_stdin_patIsValidatedAndStored(t *testing.T) {
	env := newSecretArgumentEnv(t)
	require.NoError(t, InitWhoAmIWorkflow(env.engine))
	env.server.RegisterPAT(testPAT)
	env.pipeToStdin(t, testPAT+"\n")

	err := env.authWith(t, map[string]string{stdinFlag: "true"})

	require.NoError(t, err)
	assert.Equal(t, testPAT, env.storedValues(t)[auth.CONFIG_KEY_TOKEN], "snyk config get api returns the PAT")
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
			want:  []string{"--" + auth.PARAMETER_CLIENT_ID, "browser login"},
		},
		"PAT with auth type oauth and without --client-id": {
			piped:  testPAT,
			values: map[string]string{AuthTypeParameter: auth.AUTH_TYPE_OAUTH},
			want:   []string{"--" + auth.PARAMETER_CLIENT_ID, "browser login", "without --" + AuthTypeParameter},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			env := newSecretArgumentEnv(t)
			env.server.RegisterClientSecret("client-1", "shared-secret-1")
			env.pipeToStdin(t, tc.piped)
			values := map[string]string{stdinFlag: "true"}
			maps.Copy(values, tc.values)

			err := env.authWith(t, values)

			detail := invalidFlagDetail(t, err)
			for _, want := range tc.want {
				assert.Contains(t, detail, want)
			}
			assert.Equal(t, 0, env.server.TokenAttempts())
			assert.Empty(t, env.server.CredentialHeaders(), "no request carried a credential")
		})
	}
}

func Test_auth_stdin_sharedSecretIsNotStored(t *testing.T) {
	env := newSecretArgumentEnv(t)
	env.server.RegisterClientSecret("client-1", "shared-secret-1")
	env.pipeToStdin(t, "shared-secret-1\n")

	err := env.authWith(t, map[string]string{auth.PARAMETER_CLIENT_ID: "client-1", stdinFlag: "true"})

	require.NoError(t, err)
	for _, file := range filesUnder(t, env.home) {
		content, readErr := os.ReadFile(file)
		require.NoError(t, readErr)
		assert.NotContains(t, string(content), "shared-secret-1", file)
	}
}
