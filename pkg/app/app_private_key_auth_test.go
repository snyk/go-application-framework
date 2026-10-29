package app

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/internal/machineenrollment/enrollmenttest"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configtest"
	"github.com/snyk/go-application-framework/pkg/configuration"
	localworkflows "github.com/snyk/go-application-framework/pkg/local_workflows"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func newFileBackedAppEngine(t *testing.T) workflow.Engine {
	t.Helper()
	config := configuration.NewWithOpts(configuration.WithFiles("snyk"))
	config.Set(configuration.MACHINE_ID, "supplied-machine-id")
	engine := CreateAppEngineWithOptions(WithConfiguration(config))
	require.NoError(t, engine.Init())
	return engine
}

// newPrivateKeyLoginServer isolates the user's configuration and returns a fake service that knows
// client-1, and the PEM of client-1's key.
func newPrivateKeyLoginServer(t *testing.T) (*enrollmenttest.Server, string) {
	t.Helper()
	configtest.IsolateEnvironmentForTest(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	server := enrollmenttest.NewServer(t)
	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	server.RegisterClient("client-1", &key.PublicKey)
	keyPEM, err := machineenrollment.EncodeKeyPEM(key)
	require.NoError(t, err)
	return server, string(keyPEM)
}

func loginWithPrivateKey(engine workflow.Engine, keyPEM string) error {
	loginConfig := engine.GetConfiguration().Clone()
	loginConfig.Set(auth.PARAMETER_CLIENT_ID, "client-1")
	loginConfig.Set(auth.PARAMETER_CLIENT_SECRET, keyPEM)
	_, err := engine.InvokeWithConfig(localworkflows.WORKFLOWID_AUTH, loginConfig)
	return err
}

func Test_CreateAppEngine_afterAPrivateKeyLoginLaterProcessesUseTheAPIURLOfTheMintedToken(t *testing.T) {
	server, keyPEM := newPrivateKeyLoginServer(t)
	login := newFileBackedAppEngine(t)
	login.GetConfiguration().Set(configuration.API_URL, server.URL)
	require.NoError(t, loginWithPrivateKey(login, keyPEM))

	later := newFileBackedAppEngine(t)

	apiURL := later.GetConfiguration().GetString(configuration.API_URL)
	require.Equal(t, server.URL, apiURL, "a later process must not fall back to the default API URL")
	res, err := later.GetNetworkAccess().GetHttpClient().Get(apiURL + "/rest/whoami")
	require.NoError(t, err)
	_ = res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)
}

func Test_CreateAppEngine_aPrivateKeyLoginIgnoresTheAPIURLOfTheStoredUserLogin(t *testing.T) {
	server, keyPEM := newPrivateKeyLoginServer(t)
	login := newFileBackedAppEngine(t)
	config := login.GetConfiguration()
	config.PersistInStorage(auth.CONFIG_KEY_OAUTH_TOKEN)
	config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, createOAuthTokenWithAudience(t, "http://127.0.0.1:1"))
	config.Set(configuration.API_URL, server.URL)

	require.NoError(t, loginWithPrivateKey(login, keyPEM))

	assert.Equal(t, 1, server.TokenRequests)
	assert.Equal(t, server.URL, newFileBackedAppEngine(t).GetConfiguration().GetString(configuration.API_URL))
}
