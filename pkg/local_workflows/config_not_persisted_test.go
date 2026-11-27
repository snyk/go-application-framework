package localworkflows

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// configWithoutHomeDirectory returns a configuration with the snyk file and no home directory, run in an empty working
// directory.
func configWithoutHomeDirectory(t *testing.T) (config configuration.Configuration, workingDir string) {
	t.Helper()
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	workingDir = t.TempDir()
	t.Chdir(workingDir)

	config = configuration.NewWithOpts(configuration.WithFiles("snyk"))
	require.Nil(t, config.GetStorage(), "precondition: no storage without a home directory")
	return config, workingDir
}

// noHomeDirectoryReason is part of the detail when the home directory could not be determined.
const noHomeDirectoryReason = "Set the HOME environment variable (USERPROFILE on Windows) to an absolute path"

func assertEmptyDir(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "nothing is written to the working directory")
}

func assertConfigNotPersistedError(t *testing.T, err error, wantDetail string, wantReason string) {
	t.Helper()
	require.IsType(t, snyk_errors.Error{}, err, "the error must not be wrapped")
	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr)
	assert.Equal(t, "SNYK-CLI-0042", catalogErr.ErrorCode)
	assert.Equal(t, "Configuration cannot be saved", catalogErr.Title)
	assert.Contains(t, catalogErr.Detail, wantDetail)
	assert.Contains(t, catalogErr.Detail, wantReason)
}

func Test_AuthEntryPointDI_WithoutStorage_RefusesBeforeTheLogin(t *testing.T) {
	const existingToken = "existing-oauth-token"

	tests := map[string]func(config configuration.Configuration){
		"oauth": func(config configuration.Configuration) {
			config.Set(AuthTypeParameter, auth.AUTH_TYPE_OAUTH)
		},
		"pat": func(config configuration.Configuration) {
			config.Set(AuthTypeParameter, auth.AUTH_TYPE_PAT)
			config.Set(ConfigurationNewAuthenticationToken, "snyk_uat.12345678.payload.signature")
		},
		// the legacy CLI would write the token to a file that the next run does not read
		"token": func(config configuration.Configuration) {
			config.Set(AuthTypeParameter, auth.AUTH_TYPE_TOKEN)
		},
	}
	for name, setAuthType := range tests {
		t.Run(name, func(t *testing.T) {
			globalConfig, workingDir := configWithoutHomeDirectory(t)
			globalConfig.Set(auth.CONFIG_KEY_OAUTH_TOKEN, existingToken)
			localConfig := globalConfig.Clone()
			setAuthType(localConfig)

			mockCtl := gomock.NewController(t)
			logger := zerolog.New(&bytes.Buffer{})
			// no expectations on the authenticator or engine.Invoke: the login must not start
			engine := mocks.NewMockEngine(mockCtl)
			engine.EXPECT().GetConfiguration().Return(globalConfig).AnyTimes()
			authenticator := mocks.NewMockAuthenticator(mockCtl)
			invocationCtx := mocks.NewMockInvocationContext(mockCtl)
			invocationCtx.EXPECT().GetConfiguration().Return(localConfig).AnyTimes()
			invocationCtx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
			invocationCtx.EXPECT().GetAnalytics().Return(analytics.New()).AnyTimes()

			err := AuthEntryPointDI(invocationCtx, &logger, engine, authenticator)

			assertConfigNotPersistedError(t, err, "The login is refused", noHomeDirectoryReason)
			for _, config := range []configuration.Configuration{localConfig, globalConfig} {
				assert.Equal(t, existingToken, config.GetString(auth.CONFIG_KEY_OAUTH_TOKEN), "the existing token is not cleared")
			}
			assertEmptyDir(t, workingDir)
		})
	}
}

func Test_AuthEntryPointDI_ProfileWithoutStorage_RefusesBeforeTheLogin(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	globalConfig := configuration.NewWithOpts(configuration.WithFiles("snyk"))
	require.NotNil(t, globalConfig.GetStorage(), "precondition: the global configuration has storage")
	profileFile := filepath.Join(t.TempDir(), "work.json")
	require.NoError(t, os.WriteFile(profileFile, []byte("{not json"), 0o600))
	profileConfig := configuration.NewWithOpts(configuration.WithPinnedFile(profileFile))
	require.Nil(t, profileConfig.GetStorage(), "precondition: the profile file cannot be used")
	localConfig := profileConfig.Clone()
	localConfig.Set(AuthTypeParameter, auth.AUTH_TYPE_OAUTH)

	mockCtl := gomock.NewController(t)
	logger := zerolog.New(&bytes.Buffer{})
	// no expectations on the authenticator or engine.Invoke: the login must not start
	engine := mocks.NewMockEngine(mockCtl)
	engine.EXPECT().GetConfiguration().Return(globalConfig).AnyTimes()
	authenticator := mocks.NewMockAuthenticator(mockCtl)
	invocationCtx := mocks.NewMockInvocationContext(mockCtl)
	invocationCtx.EXPECT().GetConfiguration().Return(localConfig).AnyTimes()
	invocationCtx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocationCtx.EXPECT().GetAnalytics().Return(analytics.New()).AnyTimes()

	err := AuthEntryPointDI(invocationCtx, &logger, engine, authenticator)

	assertConfigNotPersistedError(t, err, "The login is refused", "the configured configuration file cannot be used")
}

func Test_ConfigEnvironment_entryPoint_WithoutStorage_RefusesAndChangesNothing(t *testing.T) {
	stubLookupHostResolving(t, "api.eu.snyk.io")
	config, workingDir := configWithoutHomeDirectory(t)
	engine := workflow.NewWorkFlowEngine(config)
	logger := zerolog.New(io.Discard)

	config.Set(configuration.INPUT_DIRECTORY, "eu")
	config.Set(configuration.API_URL, "https://api.snyk.io")
	config.Set(configuration.ORGANIZATION, "existing-org")

	mockctl := gomock.NewController(t)
	invocationCtx := mocks.NewMockInvocationContext(mockctl)
	invocationCtx.EXPECT().GetConfiguration().Return(config)
	invocationCtx.EXPECT().GetEnhancedLogger().Return(&logger)
	invocationCtx.EXPECT().GetUserInterface().Return(ui.DefaultUi())
	require.NoError(t, InitConfigWorkflow(engine))

	outputData, outputErr := configEnvironmentWorkflowEntryPoint(invocationCtx, nil)

	assert.Nil(t, outputData)
	assertConfigNotPersistedError(t, outputErr, "The environment is not changed", noHomeDirectoryReason)
	assert.Equal(t, "https://api.snyk.io", config.GetString(configuration.API_URL), "the environment is unchanged")
	assert.Equal(t, "existing-org", config.GetString(configuration.ORGANIZATION), "the organization is not cleared")
	assertEmptyDir(t, workingDir)
}
