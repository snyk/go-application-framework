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

func Test_CreateAppEngine_afterAPrivateKeyLoginLaterProcessesUseTheAPIURLOfTheMintedToken(t *testing.T) {
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

	login := newFileBackedAppEngine(t)
	login.GetConfiguration().Set(configuration.API_URL, server.URL)
	loginConfig := login.GetConfiguration().Clone()
	loginConfig.Set(auth.PARAMETER_CLIENT_ID, "client-1")
	loginConfig.Set(auth.PARAMETER_CLIENT_SECRET, string(keyPEM))
	_, err = login.InvokeWithConfig(localworkflows.WORKFLOWID_AUTH, loginConfig)
	require.NoError(t, err)

	later := newFileBackedAppEngine(t)

	apiURL := later.GetConfiguration().GetString(configuration.API_URL)
	require.Equal(t, server.URL, apiURL, "a later process must not fall back to the default API URL")
	res, err := later.GetNetworkAccess().GetHttpClient().Get(apiURL + "/rest/whoami")
	require.NoError(t, err)
	_ = res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)
}
