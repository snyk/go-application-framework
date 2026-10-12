package machine_workflow

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/internal/machineenrollment/enrollmenttest"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/config_utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_MachineWorkflows_registration(t *testing.T) {
	engine := workflow.NewWorkFlowEngine(configuration.NewWithOpts())

	require.NoError(t, InitMachineWorkflows(engine))

	for _, id := range []workflow.Identifier{WORKFLOWID_MACHINE_ENROLL, WORKFLOWID_MACHINE_STATUS} {
		entry, ok := engine.GetWorkflow(id)
		require.True(t, ok, id)
		flags := workflow.FlagsetFromConfigurationOptions(entry.GetConfigurationOptions())
		assert.True(t, config_utils.IsExperimental(flags), id)
	}
}

type fixture struct {
	srv          *enrollmenttest.Server
	keychain     *enrollmenttest.Keychain
	config       configuration.Configuration
	globalConfig configuration.Configuration
	keyFile      string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ca := enrollmenttest.NewCA(t, "Device Management CA")
	f := &fixture{
		srv:          enrollmenttest.NewServer(t, ca),
		keychain:     &enrollmenttest.Keychain{Identities: []*enrollmenttest.Identity{ca.Issue(t, "device-identity")}},
		globalConfig: configuration.NewWithOpts(),
		keyFile:      filepath.Join(t.TempDir(), "machine-client", "key.pem"),
	}
	f.globalConfig.Set(configuration.API_URL, f.srv.URL)
	f.globalConfig.Set(configuration.FF_OAUTH_AUTH_FLOW_ENABLED, true)
	f.globalConfig.Set(machineenrollment.CONFIG_KEY_CLIENT_KEY_FILE, f.keyFile)
	f.config = f.globalConfig.Clone()
	return f
}

func (f *fixture) enroll(t *testing.T) string {
	t.Helper()
	logger := zerolog.Nop()
	message, err := enroll(context.Background(), f.config, f.globalConfig, http.DefaultClient, f.keychain, &logger)
	require.NoError(t, err)
	return message
}

func Test_enroll(t *testing.T) {
	f := newFixture(t)
	f.globalConfig.Set(auth.CONFIG_KEY_OAUTH_TOKEN, `{"access_token":"a user's token"}`)
	f.config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, `{"access_token":"a user's token"}`)

	message := f.enroll(t)

	assert.Contains(t, message, "machine-1")
	assert.Contains(t, message, "client-1")
	key, err := machineenrollment.ReadKeyFile(f.keyFile)
	require.NoError(t, err)
	assert.True(t, f.srv.ClientKey("client-1").Equal(&key.PublicKey), "the stored key is the enrolled one")
	for name, c := range map[string]configuration.Configuration{"invocation": f.config, "global": f.globalConfig} {
		assert.Equal(t, "client-1", c.GetString(machineenrollment.CONFIG_KEY_CLIENT_ID), name)
		assert.Equal(t, "machine-1", c.GetString(machineenrollment.CONFIG_KEY_MACHINE_ID), name)
		assert.Equal(t, f.keyFile, c.GetString(machineenrollment.CONFIG_KEY_CLIENT_KEY_FILE), name)
		token, err := auth.GetOAuthToken(c)
		require.NoError(t, err, name)
		require.NotNil(t, token, name)
		assert.Equal(t, "token-client-1-1", token.AccessToken, "%s: the machine replaces the user", name)
	}
}

func Test_enroll_reEnrollingReplacesTheClient(t *testing.T) {
	f := newFixture(t)
	f.enroll(t)
	f.config = f.globalConfig.Clone()

	f.enroll(t)

	assert.Equal(t, "client-2", f.globalConfig.GetString(machineenrollment.CONFIG_KEY_CLIENT_ID))
	key, err := machineenrollment.ReadKeyFile(f.keyFile)
	require.NoError(t, err)
	assert.True(t, f.srv.ClientKey("client-2").Equal(&key.PublicKey))
}

func Test_enroll_refusedLeavesConfigurationAlone(t *testing.T) {
	f := newFixture(t)
	f.srv.RejectEnrollment = "This device is not in the fleet."
	logger := zerolog.Nop()

	_, err := enroll(context.Background(), f.config, f.globalConfig, http.DefaultClient, f.keychain, &logger)

	assert.ErrorContains(t, err, "This device is not in the fleet.")
	assert.Empty(t, f.globalConfig.GetString(machineenrollment.CONFIG_KEY_CLIENT_ID))
	assert.NoFileExists(t, f.keyFile)
}

func Test_status(t *testing.T) {
	f := newFixture(t)
	f.srv.Tenants = []machineenrollment.Tenant{{ID: "t-1", Name: "Tenant One"}}
	f.enroll(t)
	authenticator := auth.NewOAuth2AuthenticatorWithOpts(f.globalConfig, auth.WithHttpClient(http.DefaultClient))
	client := &http.Client{Transport: authenticating{authenticator}}

	message, err := status(context.Background(), f.globalConfig, client)

	require.NoError(t, err)
	assert.Contains(t, message, "machine-1")
	assert.Contains(t, message, "client-1")
	assert.Contains(t, message, "t-1  Tenant One")
}

func Test_status_notEnrolled(t *testing.T) {
	_, err := status(context.Background(), configuration.NewWithOpts(), http.DefaultClient)

	assert.ErrorIs(t, err, ErrNotEnrolled)
}

type authenticating struct{ authenticator auth.Authenticator }

func (a authenticating) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if err := a.authenticator.AddAuthenticationHeader(r); err != nil {
		return nil, err
	}
	return http.DefaultTransport.RoundTrip(r)
}
