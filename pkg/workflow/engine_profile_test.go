package workflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/error-catalog-golang-public/cli"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/profile"
	"github.com/snyk/go-application-framework/pkg/networking"
)

const (
	profileTestKey        = "testkey"
	profileTestOnlyKey    = "onlydefault"
	profileTestScratchKey = "scratchkey"
	profileTestAltKey     = "altkey"

	// defaultPayload is what the leaf workflow reports on the configuration of the engine.
	defaultPayload = "default-value|default-value|default-value|only-default"
	// machinePayload is what the leaf workflow reports on the "machine" profile, which lacks the default-only key.
	machinePayload = "machine-value|machine-value|machine-value|"
)

// The expected error codes come from the catalog entries themselves, so a renumbering cannot leave the tests behind.
var (
	catalogCodeInvalidName = cli.NewInvalidConfigProfileNameError("").ErrorCode
	catalogCodeUnreadable  = cli.NewConfigProfileUnreadableError("").ErrorCode
	catalogCodeDirInvalid  = cli.NewConfigProfileDirectoryInvalidError("").ErrorCode
	catalogCodeUnavailable = cli.NewConfigProfilesUnavailableError("").ErrorCode
)

type profileEnv struct {
	t       *testing.T
	dir     string
	base    configuration.Configuration
	engine  Engine
	leafMu  sync.Mutex
	leafCnt int

	// failureHook, when set before an invocation, runs in the post-invoke hook of a failed invocation.
	failureHook func(e Engine)

	hookMu    sync.Mutex
	hookErr   error
	hookValue string
	hookState hookState
}

// hookState is what a post-invoke hook sees of the engine.
type hookState struct {
	value        string // profileTestKey in the configuration of the hook
	token        string // configuration.AUTHENTICATION_TOKEN in the configuration of the hook
	networkToken string // configuration.AUTHENTICATION_TOKEN in the configuration of the network access of the hook
	sameConfig   bool   // the network access of the hook is bound to the configuration of the hook
	access       networking.NetworkAccess
}

func inspectHook(e Engine) hookState {
	cfg := e.GetConfiguration()
	netAccess := e.GetNetworkAccess()
	netCfg := netAccess.GetConfiguration()
	return hookState{
		value:        cfg.GetString(profileTestKey),
		token:        cfg.GetString(configuration.AUTHENTICATION_TOKEN),
		networkToken: netCfg.GetString(configuration.AUTHENTICATION_TOKEN),
		sameConfig:   netCfg == cfg,
		access:       netAccess,
	}
}

// newProfileBase returns a configuration whose values come from a snyk.json file in dir. It has no profile directory,
// so a test that selects a profile sets profile.DirKey itself.
func newProfileBase(dir string) configuration.Configuration {
	base := configuration.NewWithOpts(
		configuration.WithFiles(filepath.Join(dir, "snyk.json")),
		configuration.WithCachingEnabled(configuration.NoCacheExpiration),
	)
	base.Set(profileTestKey, "default-value")
	base.Set(profileTestOnlyKey, "only-default")
	return base
}

// newProfileEnv returns an initialized engine whose profile files are in its temporary directory.
func newProfileEnv(t *testing.T) *profileEnv {
	t.Helper()
	dir := t.TempDir()
	base := newProfileBase(t.TempDir())
	base.Set(profile.DirKey, dir)
	return newProfileEnvWithBase(t, dir, base)
}

// newProfileEnvWithBase returns an initialized engine that runs on base, with the profile files in dir. Its "leaf"
// workflow reports "config|engineConfig|networkConfig|onlyKey" for the configurations it sees.
func newProfileEnvWithBase(t *testing.T, dir string, base configuration.Configuration) *profileEnv {
	t.Helper()
	env := &profileEnv{t: t, dir: dir, base: base, engine: NewWorkFlowEngine(base)}

	env.register("leaf", func(ictx InvocationContext, _ []Data) ([]Data, error) {
		env.leafMu.Lock()
		env.leafCnt++
		env.leafMu.Unlock()
		payload := fmt.Sprintf("%s|%s|%s|%s",
			ictx.GetConfiguration().GetString(profileTestKey),
			ictx.GetEngine().GetConfiguration().GetString(profileTestKey),
			ictx.GetNetworkAccess().GetConfiguration().GetString(profileTestKey),
			ictx.GetConfiguration().GetString(profileTestOnlyKey),
		)
		return []Data{NewData(NewTypeIdentifier(NewWorkflowIdentifier("leaf"), "observed"), "text/plain", payload)}, nil
	})
	env.register("bound", func(ictx InvocationContext, _ []Data) ([]Data, error) {
		state := "detached"
		if ictx.GetEngine().GetNetworkAccess().GetConfiguration() == ictx.GetEngine().GetConfiguration() {
			state = "bound"
		}
		return []Data{NewData(NewTypeIdentifier(NewWorkflowIdentifier("bound"), "observed"), "text/plain", state)}, nil
	})
	env.register("outer", func(ictx InvocationContext, _ []Data) ([]Data, error) {
		return ictx.GetEngine().Invoke(NewWorkflowIdentifier("leaf"))
	})
	// scratch reports the scratch key it sees, then sets it on its configuration.
	env.register("scratch", func(ictx InvocationContext, _ []Data) ([]Data, error) {
		seen := ictx.GetConfiguration().GetString(profileTestScratchKey)
		ictx.GetConfiguration().Set(profileTestScratchKey, "dirty")
		return []Data{NewData(NewTypeIdentifier(NewWorkflowIdentifier("scratch"), "observed"), "text/plain", seen)}, nil
	})
	// switcher selects a profile that does not exist, then invokes the leaf workflow as a nested invocation.
	env.register("switcher", func(ictx InvocationContext, _ []Data) ([]Data, error) {
		env.selectProfile("missing")
		return ictx.GetEngine().Invoke(NewWorkflowIdentifier("leaf"))
	})

	require.NoError(t, AddPostInvokeHook(env.engine, func(_ context.Context, e Engine, result InvokeOutput) {
		if env.failureHook != nil && result.GetError() != nil {
			env.failureHook(e)
		}
		env.hookMu.Lock()
		defer env.hookMu.Unlock()
		env.hookErr = result.GetError()
		env.hookValue = e.GetConfiguration().GetString(profileTestKey)
		env.hookState = inspectHook(e)
	}))
	require.NoError(t, env.engine.Init())
	return env
}

// register adds a workflow to the engine of the environment.
func (env *profileEnv) register(name string, cb Callback) {
	env.t.Helper()
	_, err := env.engine.Register(NewWorkflowIdentifier(name), ConfigurationOptionsFromFlagset(pflag.NewFlagSet(name, pflag.ContinueOnError)), cb)
	require.NoError(env.t, err)
}

// writeProfileFile writes the profile name, holding the value of profileTestKey, to profileDir/name.json.
func writeProfileFile(t *testing.T, profileDir, name, value string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(profileDir, 0o755))
	content := fmt.Sprintf(`{%q:%q}`, profileTestKey, value)
	require.NoError(t, os.WriteFile(filepath.Join(profileDir, name+".json"), []byte(content), 0o600))
}

func (env *profileEnv) writeProfile(name, value string) {
	env.t.Helper()
	writeProfileFile(env.t, env.dir, name, value)
}

func (env *profileEnv) selectProfile(name string) {
	env.base.Set(profile.ConfigKey, name)
}

// impl returns the engine implementation, to reach the profile registry of the engine.
func (env *profileEnv) impl() *EngineImpl {
	env.t.Helper()
	impl, ok := env.engine.(*EngineImpl)
	require.True(env.t, ok)
	return impl
}

// setRegistry makes the engine use reg as its profile registry for the profile directory that is set now.
func (env *profileEnv) setRegistry(reg profile.Registry) {
	env.t.Helper()
	impl := env.impl()
	impl.profiles, impl.profilesDir = reg, env.base.GetString(profile.DirKey)
}

func (env *profileEnv) leafRuns() int {
	env.leafMu.Lock()
	defer env.leafMu.Unlock()
	return env.leafCnt
}

// report returns the payload of the single output of an invocation.
func report(t *testing.T, output []Data, err error) string {
	t.Helper()
	require.NoError(t, err)
	require.Len(t, output, 1)
	payload, ok := output[0].GetPayload().(string)
	require.True(t, ok)
	return payload
}

// catalogDetail returns the detail of the error-catalog error in the chain of err, or "" when there is none. The message
// of a catalog error is only its title, so the detail is what names the value that went wrong.
func catalogDetail(err error) string {
	var catalogErr snyk_errors.Error
	if errors.As(err, &catalogErr) {
		return catalogErr.Detail
	}
	return ""
}

// assertErrMatches checks that err is wantErr, when set, and contains wantMsg, when set.
func assertErrMatches(t *testing.T, err, wantErr error, wantMsg string) {
	t.Helper()
	if wantErr != nil {
		assert.ErrorIs(t, err, wantErr)
	}
	if wantMsg != "" {
		assert.ErrorContains(t, err, wantMsg)
	}
}

// assertCatalogCode checks that err carries an error-catalog error with the code.
func assertCatalogCode(t *testing.T, err error, code string) {
	t.Helper()
	var catalogErr snyk_errors.Error
	if assert.ErrorAs(t, err, &catalogErr) {
		assert.Equal(t, code, catalogErr.ErrorCode)
	}
}

// assertFailedInvocation checks a failed selection: the invocation fails with the error, the workflow does not run, and
// the post-invoke hooks see the same error and an empty configuration with a network access bound to it that reads no
// environment.
func assertFailedInvocation(t *testing.T, env *profileEnv, output []Data, err, wantErr error, wantMsg string) {
	t.Helper()
	assertErrMatches(t, err, wantErr, wantMsg)
	assert.Empty(t, output)
	assert.Equal(t, 0, env.leafRuns(), "the workflow must not run")

	env.hookMu.Lock()
	defer env.hookMu.Unlock()
	assertErrMatches(t, env.hookErr, wantErr, wantMsg)
	assert.Empty(t, env.hookValue, "post-invoke hooks must not see the default configuration")
	assert.Empty(t, env.hookState.token, "the hook configuration must not read the environment")
	assert.Empty(t, env.hookState.networkToken, "the hook network access must not read the environment")
	assert.True(t, env.hookState.sameConfig, "the hook network access must be bound to the hook configuration")
	assert.NotSame(t, env.engine.GetNetworkAccess(), env.hookState.access, "the hook must not get the network access of the engine")
}

// Test_Engine_Profile_NetworkAccessIsBoundToTheEngineConfiguration checks that the network access an invocation reaches
// through its engine is bound to the configuration the engine reports, for the default profile and for a selected one.
func Test_Engine_Profile_NetworkAccessIsBoundToTheEngineConfiguration(t *testing.T) {
	env := newProfileEnv(t)
	env.writeProfile("machine", "machine-value")

	for _, name := range []string{"", "machine"} {
		env.selectProfile(name)
		output, err := env.engine.Invoke(NewWorkflowIdentifier("bound"))
		assert.Equal(t, "bound", report(t, output, err), "profile %q", name)
	}
}

// Test_Engine_Profile_RootRunsOnSelectedProfile checks that a root invocation runs on the selected profile, and that a
// later selection makes the next root invocation run on the other profile.
func Test_Engine_Profile_RootRunsOnSelectedProfile(t *testing.T) {
	env := newProfileEnv(t)
	env.writeProfile("first", "first-value")
	env.writeProfile("second", "second-value")

	env.selectProfile("first")
	output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	// the profile file holds the value, and the default-only key is not part of the profile
	assert.Equal(t, "first-value|first-value|first-value|", report(t, output, err))

	env.selectProfile("second")
	output, err = env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assert.Equal(t, "second-value|second-value|second-value|", report(t, output, err))
}

// Test_Engine_Profile_FailedSelectionFailsTheInvocation checks each way a root invocation can fail to select its profile.
func Test_Engine_Profile_FailedSelectionFailsTheInvocation(t *testing.T) {
	t.Setenv("SNYK_TOKEN", "token-from-environment") // no failed selection may read the environment

	tests := []struct {
		name         string
		setup        func(env *profileEnv)
		wantErr      error
		wantCode     string                // optional: the error-catalog code that the invocation error carries
		wantMsg      string                // optional: text of the error message
		wantDetail   string                // optional: text that the detail of the error-catalog error contains
		fix          func(env *profileEnv) // optional: fixing the cause lets the same selection succeed
		wantAfterFix string
	}{
		{
			name: "corrupt_profile_file_fails_the_invocation",
			setup: func(env *profileEnv) {
				require.NoError(env.t, os.WriteFile(filepath.Join(env.dir, "broken.json"), []byte("{not json"), 0o600))
				env.selectProfile("broken")
			},
			wantErr:  profile.ErrCorrupt,
			wantCode: catalogCodeUnreadable,
		},
		{
			name:     "name_with_a_path_separator_is_rejected",
			setup:    func(env *profileEnv) { env.selectProfile("../escape") },
			wantErr:  profile.ErrInvalidName,
			wantCode: catalogCodeInvalidName,
		},
		{
			name:     "name_with_a_space_is_rejected",
			setup:    func(env *profileEnv) { env.selectProfile("Bad Name") },
			wantErr:  profile.ErrInvalidName,
			wantCode: catalogCodeInvalidName,
		},
		{
			name:       "nil_profile_fails_the_invocation",
			setup:      func(env *profileEnv) { env.setRegistry(nilProfileRegistry{}); env.selectProfile("anything") },
			wantErr:    errProfileWithoutConfig,
			wantCode:   catalogCodeUnavailable,
			wantDetail: "anything",
		},
		{
			name:       "profile_without_configuration_fails_the_invocation",
			setup:      func(env *profileEnv) { env.setRegistry(nilConfigRegistry{}); env.selectProfile("machine") },
			wantErr:    errProfileWithoutConfig,
			wantCode:   catalogCodeUnavailable,
			wantDetail: "machine",
		},
		{
			name: "relative_base_dir_fails_the_selection_and_is_retried_after_the_fix",
			setup: func(env *profileEnv) {
				env.base.Set(profile.DirKey, "relative-profiles")
				env.selectProfile("machine")
			},
			wantDetail:   "absolute path",
			wantCode:     catalogCodeDirInvalid,
			fix:          func(env *profileEnv) { env.base.Set(profile.DirKey, env.dir) },
			wantAfterFix: machinePayload,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newProfileEnv(t)
			env.writeProfile("machine", "machine-value")
			tc.setup(env)

			output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
			assertFailedInvocation(t, env, output, err, tc.wantErr, tc.wantMsg)
			if tc.wantCode != "" {
				assertCatalogCode(t, err, tc.wantCode)
				env.hookMu.Lock()
				assertCatalogCode(t, env.hookErr, tc.wantCode)
				env.hookMu.Unlock()
			}

			if tc.wantDetail != "" {
				assert.Contains(t, catalogDetail(err), tc.wantDetail)
				env.hookMu.Lock()
				assert.Contains(t, catalogDetail(env.hookErr), tc.wantDetail)
				env.hookMu.Unlock()
			}

			if tc.fix != nil {
				tc.fix(env)
				output, err = env.engine.Invoke(NewWorkflowIdentifier("leaf"))
				assert.Equal(t, tc.wantAfterFix, report(t, output, err), "the failure must not be cached")
			}
		})
	}
}

// Test_Engine_Profile_PersistedWriteCreatesTheSelectedProfileFile checks that a selected profile without a file runs
// empty, and that a value persisted by a workflow on the configuration it reaches creates the profile file.
func Test_Engine_Profile_PersistedWriteCreatesTheSelectedProfileFile(t *testing.T) {
	profileDir := filepath.Join(t.TempDir(), "not-yet")
	base := newProfileBase(t.TempDir())
	base.Set(profile.DirKey, profileDir)
	env := newProfileEnvWithBase(t, profileDir, base)
	// as the auth workflow does, the workflow registers the key on the configuration it reaches, because a clone does
	// not inherit the persisted keys
	env.register("persist", func(ictx InvocationContext, _ []Data) ([]Data, error) {
		ictx.GetConfiguration().PersistInStorage(profileTestKey)
		ictx.GetConfiguration().Set(profileTestKey, "persisted-value")
		return []Data{NewData(NewTypeIdentifier(NewWorkflowIdentifier("persist"), "observed"), "text/plain", "ok")}, nil
	})
	env.selectProfile("new")

	output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assert.Equal(t, "|||", report(t, output, err), "a profile without a file is empty")
	_, statErr := os.Stat(profileDir)
	assert.ErrorIs(t, statErr, os.ErrNotExist, "reading must create nothing")

	output, err = env.engine.Invoke(NewWorkflowIdentifier("persist"))
	assert.Equal(t, "ok", report(t, output, err))
	content, err := os.ReadFile(filepath.Join(profileDir, "new.json"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"testkey":"persisted-value"}`, string(content))

	// an engine that starts after the write, as a later process does, reads the value from the file
	base = newProfileBase(t.TempDir())
	base.Set(profile.DirKey, profileDir)
	later := newProfileEnvWithBase(t, profileDir, base)
	later.selectProfile("new")
	output, err = later.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assert.Equal(t, "persisted-value|persisted-value|persisted-value|", report(t, output, err))
}

// Test_Engine_Profile_InvocationWithoutSelectionKeepsItsConfiguration checks the invocations that do not select a profile:
// a root without a key or with the default name, an invocation with its own configuration, and nested invocations.
func Test_Engine_Profile_InvocationWithoutSelectionKeepsItsConfiguration(t *testing.T) {
	custom := configuration.NewInMemory()
	custom.Set(profileTestKey, "custom-value")

	tests := []struct {
		name     string
		key      string
		workflow string
		opts     []EngineInvokeOption
		want     string
	}{
		{name: "empty_key_uses_the_engine_configuration", key: "", workflow: "leaf", want: defaultPayload},
		{name: "default_name_uses_the_engine_configuration", key: profile.DefaultName, workflow: "leaf", want: defaultPayload},
		{name: "invocation_with_its_own_configuration_replaces_the_selection", key: "missing", workflow: "leaf",
			opts: []EngineInvokeOption{WithConfig(custom)}, want: "custom-value|default-value|custom-value|"},
		{name: "nested_invocation_keeps_the_profile_of_its_root", key: "machine", workflow: "outer", want: machinePayload},
		{name: "nested_invocation_ignores_a_later_selection", key: "machine", workflow: "switcher", want: machinePayload},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newProfileEnv(t)
			env.writeProfile("machine", "machine-value")
			env.selectProfile(tc.key)

			output, err := env.engine.Invoke(NewWorkflowIdentifier(tc.workflow), tc.opts...)
			assert.Equal(t, tc.want, report(t, output, err))
		})
	}
}

// Test_Engine_Profile_NoRegistryIsBuiltForTheDefaultProfile checks that selecting the default profile neither reads the
// profile directory nor builds a registry.
func Test_Engine_Profile_NoRegistryIsBuiltForTheDefaultProfile(t *testing.T) {
	base := newProfileBase(t.TempDir())
	var dirReads atomic.Int32
	base.AddDefaultValue(profile.DirKey, func(_ configuration.Configuration, existing interface{}) (interface{}, error) {
		dirReads.Add(1)
		return existing, nil
	})
	env := newProfileEnvWithBase(t, t.TempDir(), base)

	for _, name := range []string{"", profile.DefaultName} {
		env.selectProfile(name)
		output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
		assert.Equal(t, defaultPayload, report(t, output, err), "profile %q", name)
	}
	assert.Equal(t, int32(0), dirReads.Load(), "the default profile must not read the profile directory")
	assert.Nil(t, env.impl().profiles, "the default profile must not build a registry")
}

// Test_Engine_Profile_ConcurrentInvocations checks that concurrent nested invocations on a selected profile all see it.
func Test_Engine_Profile_ConcurrentInvocations(t *testing.T) {
	env := newProfileEnv(t)
	env.writeProfile("machine", "machine-value")
	env.selectProfile("machine")

	const workers = 16
	var wg sync.WaitGroup
	reports := make([]string, workers)
	errs := make([]error, workers)
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var output []Data
			output, errs[i] = env.engine.Invoke(NewWorkflowIdentifier("outer"))
			if errs[i] == nil && len(output) == 1 {
				payload, ok := output[0].GetPayload().(string)
				assert.True(t, ok, "payload of worker %d is a string", i)
				reports[i] = payload
			}
		}()
	}
	wg.Wait()
	for i := range workers {
		require.NoError(t, errs[i])
		assert.Equal(t, machinePayload, reports[i])
	}
}

type nilProfileRegistry struct{}

//nolint:nilnil // the registry breaks its contract on purpose: the engine must fail the invocation, not run it
func (nilProfileRegistry) Profile(string) (profile.Profile, error) { return nil, nil }

// nilConfigRegistry finds profiles that have no configuration.
type nilConfigRegistry struct{}

func (nilConfigRegistry) Profile(name string) (profile.Profile, error) {
	return nilConfigProfile{name: name}, nil
}

type nilConfigProfile struct{ name string }

func (p nilConfigProfile) Name() string                             { return p.name }
func (nilConfigProfile) Configuration() configuration.Configuration { return nil }

// Test_Engine_Profile_HookSeesAndIsBoundToSelectedProfile checks that the post-invoke hooks see the configuration of a
// selected profile, and that their network access is bound to it.
func Test_Engine_Profile_HookSeesAndIsBoundToSelectedProfile(t *testing.T) {
	env := newProfileEnv(t)
	env.writeProfile("machine", "machine-value")
	env.selectProfile("machine")

	_, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	require.NoError(t, err)

	env.hookMu.Lock()
	defer env.hookMu.Unlock()
	assert.NoError(t, env.hookErr)
	assert.Equal(t, "machine-value", env.hookValue, "the hook must see the configuration of the selected profile")
	assert.Equal(t, "machine-value", env.hookState.value)
	assert.True(t, env.hookState.sameConfig, "the hook network access must be bound to the hook configuration")
}

// Test_Engine_Profile_NestedInvocationFromHookAfterFailedSelectionStaysEmpty checks that a nested invocation that a
// post-invoke hook starts after a failed selection runs on the empty configuration, not on the default profile.
func Test_Engine_Profile_NestedInvocationFromHookAfterFailedSelectionStaysEmpty(t *testing.T) {
	env := newProfileEnv(t)
	env.selectProfile("../escape")

	var nestedPayload string
	var nestedErr error
	env.failureHook = func(e Engine) {
		output, err := e.Invoke(NewWorkflowIdentifier("leaf"))
		nestedErr = err
		if err == nil && len(output) == 1 {
			if payload, ok := output[0].GetPayload().(string); ok {
				nestedPayload = payload
			}
		}
	}

	output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assert.ErrorIs(t, err, profile.ErrInvalidName)
	assert.Empty(t, output)

	// Invoke returns once the hooks completed, so the hook's writes are visible here
	require.NoError(t, nestedErr)
	assert.Equal(t, "|||", nestedPayload, "the nested invocation must not read the default profile")
}

// Test_Engine_Profile_ChangedDirKeyRebuildsTheRegistry checks that a profile directory set after the first lookup on the
// same configuration is the one that later selections read, and that an unchanged directory keeps the registry and its
// profile instances.
func Test_Engine_Profile_ChangedDirKeyRebuildsTheRegistry(t *testing.T) {
	env := newProfileEnv(t)
	env.writeProfile("machine", "machine-value")
	otherDir := t.TempDir()
	writeProfileFile(t, otherDir, "machine", "other-value")
	env.selectProfile("machine")

	first, err := GetProfileRegistry(env.engine)
	require.NoError(t, err)
	firstMachine, err := first.Profile("machine")
	require.NoError(t, err)
	output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assert.Equal(t, machinePayload, report(t, output, err))

	same, err := GetProfileRegistry(env.engine)
	require.NoError(t, err)
	assert.Same(t, first, same, "an unchanged directory must keep the registry")
	sameMachine, err := same.Profile("machine")
	require.NoError(t, err)
	assert.Same(t, firstMachine, sameMachine, "a profile must keep its instance")

	env.base.Set(profile.DirKey, otherDir)
	output, err = env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assert.Equal(t, "other-value|other-value|other-value|", report(t, output, err), "the invocation must read the new directory")

	rebuilt, err := GetProfileRegistry(env.engine)
	require.NoError(t, err)
	assert.NotSame(t, first, rebuilt, "a changed directory must replace the registry")

	env.base.Set(profile.DirKey, "")
	_, err = GetProfileRegistry(env.engine)
	var catalogErr snyk_errors.Error
	require.ErrorAs(t, err, &catalogErr, "an emptied directory must not keep the registry")
	assert.Equal(t, catalogCodeDirInvalid, catalogErr.ErrorCode)
}

// Test_Engine_Profile_UnknownProfileNameRunsEmptyAndIsLoggedOnce checks that a selected profile without a file runs on an
// empty profile, creates no file, and is logged at debug level once, with the path of the file it would be stored in.
func Test_Engine_Profile_UnknownProfileNameRunsEmptyAndIsLoggedOnce(t *testing.T) {
	env := newProfileEnv(t)
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	env.engine.SetLogger(&logger)
	env.selectProfile("nonexistent")

	for range 2 {
		output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
		assert.Equal(t, "|||", report(t, output, err), "a profile without a file is empty")
	}

	_, statErr := os.Stat(filepath.Join(env.dir, "nonexistent.json"))
	assert.ErrorIs(t, statErr, os.ErrNotExist, "the typo must not create a profile file")
	want := fmt.Sprintf("profile %q has no file yet, using an empty profile (%s)", "nonexistent", filepath.Join(env.dir, "nonexistent.json"))
	var profileMessages []string
	for _, message := range debugMessages(t, logs.String()) {
		if strings.HasPrefix(message, "profile ") {
			profileMessages = append(profileMessages, message)
		}
	}
	assert.Equal(t, []string{want}, profileMessages)
}

// debugMessages returns the messages of the debug entries in the JSON log output.
func debugMessages(t *testing.T, logOutput string) []string {
	t.Helper()
	var messages []string
	for line := range strings.SplitSeq(strings.TrimSpace(logOutput), "\n") {
		if line == "" {
			continue
		}
		var entry struct {
			Level   string `json:"level"`
			Message string `json:"message"`
		}
		require.NoError(t, json.Unmarshal([]byte(line), &entry))
		if entry.Level == zerolog.DebugLevel.String() {
			messages = append(messages, entry.Message)
		}
	}
	return messages
}

// Test_Engine_Profile_EnvironmentSelectsTheProfile pins which environment variables select the profile of an engine whose
// configuration comes from configuration.New, which reads the environment without a prefix. The unprefixed variables
// select the profile and its directory, and a prefixed variable is not read unless the application registers it.
func Test_Engine_Profile_EnvironmentSelectsTheProfile(t *testing.T) {
	dir := t.TempDir()
	writeProfileFile(t, dir, "machine", "machine-value")

	t.Run("unprefixed_variables_select_the_profile_and_its_directory", func(t *testing.T) {
		t.Setenv("CONFIG_PROFILE", "machine")
		t.Setenv("CONFIG_PROFILE_DIR", dir)
		base := configuration.New()
		base.Set(profileTestKey, "default-value")
		env := newProfileEnvWithBase(t, dir, base)

		output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
		assert.Equal(t, machinePayload, report(t, output, err))
	})

	t.Run("prefixed_variables_are_not_read", func(t *testing.T) {
		t.Setenv("CONFIG_PROFILE", "")
		t.Setenv("CONFIG_PROFILE_DIR", "")
		t.Setenv("SNYK_CONFIG_PROFILE", "machine")
		t.Setenv("SNYK_CONFIG_PROFILE_DIR", dir)
		base := configuration.New()
		base.Set(profileTestKey, "default-value")
		env := newProfileEnvWithBase(t, dir, base)

		output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
		assert.Equal(t, "default-value|default-value|default-value|", report(t, output, err))
	})
}

// Test_Engine_Profile_InvocationChangesStayInItsConfiguration checks that a change a workflow makes to its configuration
// neither reaches the profile nor the invocations that follow.
func Test_Engine_Profile_InvocationChangesStayInItsConfiguration(t *testing.T) {
	env := newProfileEnv(t)
	env.writeProfile("machine", "machine-value")
	env.selectProfile("machine")

	for range 2 {
		output, err := env.engine.Invoke(NewWorkflowIdentifier("scratch"))
		assert.Empty(t, report(t, output, err), "a later invocation must not see the change of an earlier one")
	}

	registry, err := env.impl().profileRegistry()
	require.NoError(t, err)
	p, err := registry.Profile("machine")
	require.NoError(t, err)
	assert.Empty(t, p.Configuration().GetString(profileTestScratchKey), "the profile must not see the change")
}

// Test_Engine_Profile_RegistryFollowsSetConfiguration checks that the registry is kept while the configuration stays the
// same, and that SetConfiguration replaces it with one that derives from the new configuration.
func Test_Engine_Profile_RegistryFollowsSetConfiguration(t *testing.T) {
	env := newProfileEnv(t)
	env.writeProfile("machine", "machine-value")
	env.selectProfile("machine")
	env.register("probe", func(ictx InvocationContext, _ []Data) ([]Data, error) {
		cfg := ictx.GetConfiguration()
		payload := cfg.GetString(profileTestKey) + "|" + cfg.GetString(profileTestAltKey)
		return []Data{NewData(NewTypeIdentifier(NewWorkflowIdentifier("probe"), "observed"), "text/plain", payload)}, nil
	})

	first, err := GetProfileRegistry(env.engine)
	require.NoError(t, err)
	second, err := GetProfileRegistry(env.engine)
	require.NoError(t, err)
	assert.Same(t, first, second, "the registry must be kept while the configuration stays the same")

	output, err := env.engine.Invoke(NewWorkflowIdentifier("probe"))
	assert.Equal(t, "machine-value|", report(t, output, err), "the first configuration has no registration for the key")

	configB := newProfileBase(t.TempDir())
	configB.Set(profile.DirKey, env.dir)
	configB.Set(profile.ConfigKey, "machine")
	configB.AddDefaultValue(profileTestAltKey, configuration.ImmutableDefaultValueFunction("from-b"))
	env.engine.SetConfiguration(configB)

	third, err := GetProfileRegistry(env.engine)
	require.NoError(t, err)
	assert.NotSame(t, first, third, "SetConfiguration must replace the registry")
	p, err := third.Profile("machine")
	require.NoError(t, err)
	assert.Equal(t, "from-b", p.Configuration().GetString(profileTestAltKey), "the profiles must derive from the new configuration")

	output, err = env.engine.Invoke(NewWorkflowIdentifier("probe"))
	assert.Equal(t, "machine-value|from-b", report(t, output, err), "the profile must derive from the new configuration")
}

// Test_Engine_Profile_WithoutDirKeyFailsSelection checks that an engine without a profile directory fails the selection of
// a profile, and that the failure reads and creates nothing in the home directory, which is a temporary directory here.
// The application sets the default directory, see the application tests.
func Test_Engine_Profile_WithoutDirKeyFailsSelection(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	env := newProfileEnvWithBase(t, t.TempDir(), newProfileBase(t.TempDir()))
	env.selectProfile("machine")

	output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assertFailedInvocation(t, env, output, err, nil, "")
	assertCatalogCode(t, err, catalogCodeDirInvalid)
	assert.Contains(t, catalogDetail(err), profile.DirKey)
	assert.Contains(t, catalogDetail(err), "absolute path")
	entries, err := os.ReadDir(home)
	require.NoError(t, err)
	assert.Empty(t, entries, "the home directory must not be touched")
}

// Test_GetProfileRegistry_IsTheRegistryOfTheSelection checks that a value set on a profile through the registry is seen by
// a root invocation that selects that profile.
func Test_GetProfileRegistry_IsTheRegistryOfTheSelection(t *testing.T) {
	env := newProfileEnv(t)
	env.writeProfile("x", "x-value")

	registry, err := GetProfileRegistry(env.engine)
	require.NoError(t, err)
	p, err := registry.Profile("x")
	require.NoError(t, err)
	p.Configuration().Set(profileTestKey, "marker")

	env.selectProfile("x")
	output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assert.Equal(t, "marker|marker|marker|", report(t, output, err), "the invocation must clone the instance the registry returns")
}

// foreignEngine is an engine that is not an EngineImpl, so it owns no profile registry.
type foreignEngine struct{ Engine }

// Test_GetProfileRegistry_IsSharedWithTheInvocationEngine checks that a workflow reaches the registry of the engine
// through the engine of its invocation context.
func Test_GetProfileRegistry_IsSharedWithTheInvocationEngine(t *testing.T) {
	env := newProfileEnv(t)
	var fromWorkflow profile.Registry
	var workflowErr error
	env.register("registry", func(ictx InvocationContext, _ []Data) ([]Data, error) {
		fromWorkflow, workflowErr = GetProfileRegistry(ictx.GetEngine())
		return nil, nil
	})

	direct, err := GetProfileRegistry(env.engine)
	require.NoError(t, err)
	_, err = env.engine.Invoke(NewWorkflowIdentifier("registry"))
	require.NoError(t, err)
	require.NoError(t, workflowErr)
	assert.Same(t, direct, fromWorkflow, "the invocation engine must expose the registry of the engine")
}

// Test_GetProfileRegistry_FailsForAnEngineWithoutProfiles checks that an engine without profiles is an error that names
// the cause, rather than a nil registry.
func Test_GetProfileRegistry_FailsForAnEngineWithoutProfiles(t *testing.T) {
	env := newProfileEnv(t)

	registry, err := GetProfileRegistry(foreignEngine{Engine: env.engine})
	assert.ErrorIs(t, err, errEngineWithoutProfiles)
	assertCatalogCode(t, err, catalogCodeUnavailable)
	assert.Nil(t, registry)
}

// Test_GetProfileRegistry_FailsForARelativeDirAndKeepsNoFailure checks that a relative profile directory is an error,
// and that the failure is not kept once the profile directory is fixed.
func Test_GetProfileRegistry_FailsForARelativeDirAndKeepsNoFailure(t *testing.T) {
	env := newProfileEnv(t)
	env.base.Set(profile.DirKey, "relative-profiles")

	registry, err := GetProfileRegistry(env.engine)
	require.Error(t, err)
	assert.Contains(t, catalogDetail(err), "absolute path")
	assert.Nil(t, registry)

	env.base.Set(profile.DirKey, env.dir)
	registry, err = GetProfileRegistry(env.engine)
	require.NoError(t, err)
	assert.NotNil(t, registry, "the failure must not be cached")
}
