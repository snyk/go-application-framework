package app

import (
	"io"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/fakeapi"
	"github.com/snyk/go-application-framework/internal/machinecredential"
	"github.com/snyk/go-application-framework/internal/machineenrollment"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

const (
	testTenantID     = "8f9a2c41-6b0e-4d7a-9c3e-1f2b3a4c5d6e"
	testDefaultOrgID = "3c1d9e2a-7b4f-4a6e-8d0c-5f1e2a3b4c5d"
	testOrgTenantID  = "b2e4f6a8-1c3d-4e5f-9a7b-0c2d4e6f8a1b"
	testUserToken    = "00000000-0000-4000-8000-000000000001"
	testOtherOrgID   = "9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b"
	testOtherTenant  = "d4c3b2a1-0f9e-4d8c-b7a6-5f4e3d2c1b0a"
)

func newTenantTestEngine(t *testing.T, config configuration.Configuration, server *fakeapi.Server) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	config.Set(configuration.API_URL, server.URL)
	engine := CreateAppEngineWithOptions(WithConfiguration(config), WithLogger(log.New(io.Discard, "", 0)))
	require.NoError(t, engine.Init())
}

func parseGlobalFlags(t *testing.T, config configuration.Configuration, args ...string) {
	t.Helper()
	globalFlags := workflow.FlagsetFromConfigurationOptions(workflow.GetGlobalConfiguration())
	require.NoError(t, globalFlags.Parse(args))
	require.NoError(t, config.AddFlagSet(globalFlags))
}

func storeMachineCredential(t *testing.T, config configuration.Configuration, server *fakeapi.Server) {
	t.Helper()
	key, err := machineenrollment.GenerateKey()
	require.NoError(t, err)
	server.RegisterClient("client-1", &key.PublicKey)
	require.NoError(t, machinecredential.Publish(config, machinecredential.Credential{ClientID: "client-1", Key: key}))
}

func Test_TenantID_EnrolledMachineReadsItsTenantFromTheBackend(t *testing.T) {
	server := fakeapi.NewServer(t)
	server.SetTenantID(testTenantID)
	config := configuration.NewWithOpts()
	storeMachineCredential(t, config, server)
	newTenantTestEngine(t, config, server)

	assert.Equal(t, testTenantID, config.GetString(configuration.TENANT))
	assert.Zero(t, server.OrgRequests())
}

func Test_TenantID_UserGetsTheTenantOfTheirDefaultOrg(t *testing.T) {
	server := fakeapi.NewServer(t)
	server.SetDefaultOrg(testDefaultOrgID)
	server.AddOrg(testDefaultOrgID, testOrgTenantID)
	config := configuration.NewWithOpts()
	config.Set(configuration.AUTHENTICATION_TOKEN, testUserToken)
	newTenantTestEngine(t, config, server)

	tenantID, err := config.GetWithError(configuration.TENANT)

	require.NoError(t, err)
	assert.Equal(t, testOrgTenantID, tenantID)
}

func Test_TenantID_UnauthenticatedEngineReportsTheOrgLookupError(t *testing.T) {
	server := fakeapi.NewServer(t)
	server.SetTenantID(testTenantID)
	server.SetDefaultOrg(testDefaultOrgID)
	server.AddOrg(testDefaultOrgID, testOrgTenantID)
	config := configuration.NewWithOpts()
	newTenantTestEngine(t, config, server)
	_, orgErr := config.GetWithError(configuration.ORGANIZATION)
	require.Error(t, orgErr)

	tenantID, err := config.GetWithError(configuration.TENANT)

	assert.Equal(t, orgErr.Error(), err.Error())
	assert.Empty(t, tenantID)
	assert.Zero(t, server.MachineSelfRequests())
	assert.Zero(t, server.OrgRequests())
}

func Test_TenantID_ExplicitValueWinsWithoutAskingTheBackend(t *testing.T) {
	server := fakeapi.NewServer(t)
	server.SetTenantID(testTenantID)
	config := configuration.NewWithOpts()
	storeMachineCredential(t, config, server)
	newTenantTestEngine(t, config, server)
	config.Set(configuration.TENANT, "explicit-tenant")

	assert.Equal(t, "explicit-tenant", config.GetString(configuration.TENANT))
	assert.Zero(t, server.MachineSelfRequests())
	assert.Zero(t, server.OrgRequests())
}

func Test_TenantID_EnvironmentVariableWinsWithoutAskingTheBackend(t *testing.T) {
	server := fakeapi.NewServer(t)
	server.SetTenantID(testTenantID)
	t.Setenv("SNYK_CFG_TENANT", "tenant-from-env")
	config := configuration.NewWithOpts(configuration.WithSupportedEnvVarPrefixes("snyk_"))
	config.AddAlternativeKeys(configuration.TENANT, []string{"snyk_cfg_tenant"})
	storeMachineCredential(t, config, server)
	newTenantTestEngine(t, config, server)

	assert.Equal(t, "tenant-from-env", config.GetString(configuration.TENANT))
	assert.Zero(t, server.MachineSelfRequests())
}

func Test_TenantID_RejectedLookupReportsTheError(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := fakeapi.NewServer(t)
			server.SetTenantID(testTenantID)
			server.FailMachineSelf(status)
			config := configuration.NewWithOpts()
			storeMachineCredential(t, config, server)
			newTenantTestEngine(t, config, server)

			tenantID, err := config.GetWithError(configuration.TENANT)

			assert.Error(t, err)
			assert.Empty(t, tenantID)
			assert.Equal(t, 1, server.MachineSelfRequests())
		})
	}
}

func Test_TenantID_UnusableMachineCredentialReportsTheErrorWithoutAskingTheBackend(t *testing.T) {
	server := fakeapi.NewServer(t)
	server.SetTenantID(testTenantID)
	config := configuration.NewWithOpts()
	config.Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, "{not json")
	newTenantTestEngine(t, config, server)

	tenantID, err := config.GetWithError(configuration.TENANT)

	assert.Error(t, err)
	assert.Empty(t, tenantID)
	assert.Zero(t, server.MachineSelfRequests())
}

func Test_TenantID_CachedConfigurationAsksTheBackendOnce(t *testing.T) {
	server := fakeapi.NewServer(t)
	server.SetTenantID(testTenantID)
	config := configuration.NewWithOpts(configuration.WithCachingEnabled(time.Hour))
	storeMachineCredential(t, config, server)
	newTenantTestEngine(t, config, server)

	assert.Equal(t, testTenantID, config.GetString(configuration.TENANT))
	assert.Equal(t, testTenantID, config.GetString(configuration.TENANT))

	assert.Equal(t, 1, server.MachineSelfRequests())
}

func Test_TenantID_CachedTenantIsNotReusedByACloneWithoutTheMachineCredential(t *testing.T) {
	server := fakeapi.NewServer(t)
	server.SetTenantID(testTenantID)
	config := configuration.NewWithOpts(configuration.WithCachingEnabled(time.Hour))
	storeMachineCredential(t, config, server)
	newTenantTestEngine(t, config, server)
	require.Equal(t, testTenantID, config.GetString(configuration.TENANT))

	clone := config.Clone()
	clone.Set(machinecredential.CONFIG_KEY_MACHINE_IDENTITY_STORAGE, "")

	assert.Empty(t, clone.GetString(configuration.TENANT))
}

func Test_TenantID_UserWhoSetsAnOrgGetsThatOrgsTenant(t *testing.T) {
	server := fakeapi.NewServer(t)
	server.SetDefaultOrg(testDefaultOrgID)
	server.AddOrg(testDefaultOrgID, testOrgTenantID)
	server.AddOrg(testOtherOrgID, testOtherTenant)
	config := configuration.NewWithOpts()
	config.Set(configuration.AUTHENTICATION_TOKEN, testUserToken)
	config.Set(configuration.ORGANIZATION, testOtherOrgID)
	newTenantTestEngine(t, config, server)

	tenantID, err := config.GetWithError(configuration.TENANT)

	require.NoError(t, err)
	assert.Equal(t, testOtherTenant, tenantID)
}

func Test_TenantID_UserWhoSetsATenantGetsExactlyThatTenantWithoutAskingTheBackend(t *testing.T) {
	server := fakeapi.NewServer(t)
	server.SetDefaultOrg(testDefaultOrgID)
	server.AddOrg(testDefaultOrgID, testOrgTenantID)
	config := configuration.NewWithOpts()
	config.Set(configuration.AUTHENTICATION_TOKEN, testUserToken)
	newTenantTestEngine(t, config, server)
	config.Set(configuration.TENANT, testOtherTenant)

	tenantID, err := config.GetWithError(configuration.TENANT)

	require.NoError(t, err)
	assert.Equal(t, testOtherTenant, tenantID)
	assert.Zero(t, server.OrgRequests())
	assert.Zero(t, server.MachineSelfRequests())
}

func Test_TenantID_OrgThatNamesNoTenantReportsAnError(t *testing.T) {
	server := fakeapi.NewServer(t)
	server.SetDefaultOrg(testDefaultOrgID)
	server.AddOrg(testDefaultOrgID, "")
	config := configuration.NewWithOpts()
	config.Set(configuration.AUTHENTICATION_TOKEN, testUserToken)
	newTenantTestEngine(t, config, server)

	tenantID, err := config.GetWithError(configuration.TENANT)

	assert.Error(t, err)
	assert.Empty(t, tenantID)
	assert.Equal(t, 1, server.OrgRequests())
}

func Test_TenantID_FailedOrgLookupReportsTheError(t *testing.T) {
	server := fakeapi.NewServer(t)
	config := configuration.NewWithOpts()
	config.Set(configuration.AUTHENTICATION_TOKEN, testUserToken)
	config.Set(configuration.ORGANIZATION, testOtherOrgID)
	newTenantTestEngine(t, config, server)

	tenantID, err := config.GetWithError(configuration.TENANT)

	assert.Error(t, err)
	assert.Empty(t, tenantID)
	assert.Equal(t, 1, server.OrgRequests())
}

func Test_TenantID_CachedUserTenantFollowsTheOrgOfAClone(t *testing.T) {
	server := fakeapi.NewServer(t)
	server.SetDefaultOrg(testDefaultOrgID)
	server.AddOrg(testDefaultOrgID, testOrgTenantID)
	server.AddOrg(testOtherOrgID, testOtherTenant)
	config := configuration.NewWithOpts(configuration.WithCachingEnabled(time.Hour))
	config.Set(configuration.AUTHENTICATION_TOKEN, testUserToken)
	newTenantTestEngine(t, config, server)

	assert.Equal(t, testOrgTenantID, config.GetString(configuration.TENANT))
	assert.Equal(t, testOrgTenantID, config.GetString(configuration.TENANT))
	assert.Equal(t, 1, server.OrgRequests())

	clone := config.Clone()
	clone.Set(configuration.ORGANIZATION, testOtherOrgID)

	assert.Equal(t, testOtherTenant, clone.GetString(configuration.TENANT))
}

func Test_TenantID_EnrolledMachinePassedTheTenantFlagGetsThatTenantWithoutAskingTheBackend(t *testing.T) {
	server := fakeapi.NewServer(t)
	server.SetTenantID(testTenantID)
	config := configuration.NewWithOpts()
	storeMachineCredential(t, config, server)
	parseGlobalFlags(t, config, "--tenant", testOtherTenant)
	newTenantTestEngine(t, config, server)

	tenantID, err := config.GetWithError(configuration.TENANT)

	require.NoError(t, err)
	assert.Equal(t, testOtherTenant, tenantID)
	assert.Zero(t, server.MachineSelfRequests())
	assert.Zero(t, server.OrgRequests())
}

func Test_TenantID_EnrolledMachineWithoutTheTenantFlagStillReadsItsOwnTenant(t *testing.T) {
	server := fakeapi.NewServer(t)
	server.SetTenantID(testTenantID)
	config := configuration.NewWithOpts()
	storeMachineCredential(t, config, server)
	parseGlobalFlags(t, config)
	newTenantTestEngine(t, config, server)

	tenantID, err := config.GetWithError(configuration.TENANT)

	require.NoError(t, err)
	assert.Equal(t, testTenantID, tenantID)
	assert.Equal(t, 1, server.MachineSelfRequests())
	assert.Zero(t, server.OrgRequests())
}
