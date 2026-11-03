package app

import (
	"bytes"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/machinecredential"
	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/internal/machineenrollment/enrollmenttest"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

const testTenantID = "8f9a2c41-6b0e-4d7a-9c3e-1f2b3a4c5d6e"

func newTenantTestEngine(t *testing.T, config configuration.Configuration, server *enrollmenttest.Server) *bytes.Buffer {
	t.Helper()
	logs := &bytes.Buffer{}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	config.Set(configuration.API_URL, server.URL)
	engine := CreateAppEngineWithOptions(WithConfiguration(config), WithLogger(log.New(logs, "", 0)))
	require.NoError(t, engine.Init())
	return logs
}

func storeMachineCredential(t *testing.T, config configuration.Configuration, server *enrollmenttest.Server) {
	t.Helper()
	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	server.RegisterClient("client-1", &key.PublicKey)
	require.NoError(t, machinecredential.Publish(config, machinecredential.Credential{ClientID: "client-1", Key: key}))
}

func Test_TenantID_EnrolledMachineReadsItsTenantFromTheBackend(t *testing.T) {
	server := enrollmenttest.NewServer(t)
	server.SetTenantID(testTenantID)
	config := configuration.NewWithOpts()
	storeMachineCredential(t, config, server)
	newTenantTestEngine(t, config, server)

	assert.Equal(t, testTenantID, config.GetString(configuration.TENANT_ID))
}

func Test_TenantID_UserAuthenticatedEngineIsEmptyWithoutAskingTheBackend(t *testing.T) {
	server := enrollmenttest.NewServer(t)
	server.SetTenantID(testTenantID)
	config := configuration.NewWithOpts()
	config.Set(configuration.AUTHENTICATION_TOKEN, "00000000-0000-4000-8000-000000000001")
	newTenantTestEngine(t, config, server)

	tenantID, err := config.GetWithError(configuration.TENANT_ID)

	require.NoError(t, err)
	assert.Empty(t, tenantID)
	assert.Zero(t, server.MachineSelfRequests())
}

func Test_TenantID_UnauthenticatedEngineIsEmptyWithoutAskingTheBackend(t *testing.T) {
	server := enrollmenttest.NewServer(t)
	server.SetTenantID(testTenantID)
	config := configuration.NewWithOpts()
	newTenantTestEngine(t, config, server)

	tenantID, err := config.GetWithError(configuration.TENANT_ID)

	require.NoError(t, err)
	assert.Empty(t, tenantID)
	assert.Zero(t, server.MachineSelfRequests())
}

func Test_TenantID_ExplicitValueWinsWithoutAskingTheBackend(t *testing.T) {
	server := enrollmenttest.NewServer(t)
	server.SetTenantID(testTenantID)
	config := configuration.NewWithOpts()
	storeMachineCredential(t, config, server)
	newTenantTestEngine(t, config, server)
	config.Set(configuration.TENANT_ID, "explicit-tenant")

	assert.Equal(t, "explicit-tenant", config.GetString(configuration.TENANT_ID))
	assert.Zero(t, server.MachineSelfRequests())
}

func Test_TenantID_EnvironmentVariableWinsWithoutAskingTheBackend(t *testing.T) {
	server := enrollmenttest.NewServer(t)
	server.SetTenantID(testTenantID)
	t.Setenv("INTERNAL_TENANT_ID", "tenant-from-env")
	config := configuration.NewWithOpts(configuration.WithSupportedEnvVarPrefixes("snyk_", "internal_"))
	storeMachineCredential(t, config, server)
	newTenantTestEngine(t, config, server)

	assert.Equal(t, "tenant-from-env", config.GetString(configuration.TENANT_ID))
	assert.Zero(t, server.MachineSelfRequests())
}

func Test_TenantID_RejectedLookupIsEmptyWithoutAnError(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := enrollmenttest.NewServer(t)
			server.SetTenantID(testTenantID)
			server.FailMachineSelf(status)
			config := configuration.NewWithOpts()
			storeMachineCredential(t, config, server)
			logs := newTenantTestEngine(t, config, server)

			tenantID, err := config.GetWithError(configuration.TENANT_ID)

			require.NoError(t, err)
			assert.Empty(t, tenantID)
			assert.Equal(t, 1, server.MachineSelfRequests())
			assert.Contains(t, logs.String(), `Failed to determine default value for "TENANT_ID"`)
		})
	}
}

func Test_TenantID_UnusableMachineCredentialIsEmptyWithoutAskingTheBackend(t *testing.T) {
	server := enrollmenttest.NewServer(t)
	server.SetTenantID(testTenantID)
	config := configuration.NewWithOpts()
	config.Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, "{not json")
	newTenantTestEngine(t, config, server)

	tenantID, err := config.GetWithError(configuration.TENANT_ID)

	require.NoError(t, err)
	assert.Empty(t, tenantID)
	assert.Zero(t, server.MachineSelfRequests())
}

func Test_TenantID_CachedConfigurationAsksTheBackendOnce(t *testing.T) {
	server := enrollmenttest.NewServer(t)
	server.SetTenantID(testTenantID)
	config := configuration.NewWithOpts(configuration.WithCachingEnabled(time.Hour))
	storeMachineCredential(t, config, server)
	newTenantTestEngine(t, config, server)

	assert.Equal(t, testTenantID, config.GetString(configuration.TENANT_ID))
	assert.Equal(t, testTenantID, config.GetString(configuration.TENANT_ID))

	assert.Equal(t, 1, server.MachineSelfRequests())
}

func Test_TenantID_CachedTenantIsNotReusedByACloneWithoutTheMachineCredential(t *testing.T) {
	server := enrollmenttest.NewServer(t)
	server.SetTenantID(testTenantID)
	config := configuration.NewWithOpts(configuration.WithCachingEnabled(time.Hour))
	storeMachineCredential(t, config, server)
	newTenantTestEngine(t, config, server)
	require.Equal(t, testTenantID, config.GetString(configuration.TENANT_ID))

	clone := config.Clone()
	clone.Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, "")

	assert.Empty(t, clone.GetString(configuration.TENANT_ID))
}
