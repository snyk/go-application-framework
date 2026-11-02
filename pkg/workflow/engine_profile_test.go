package workflow

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/profile"
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

type profileEnv struct {
	t       *testing.T
	dir     string
	base    configuration.Configuration
	engine  Engine
	leafMu  sync.Mutex
	leafCnt int

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
}

func inspectHook(e Engine) hookState {
	cfg := e.GetConfiguration()
	netCfg := e.GetNetworkAccess().GetConfiguration()
	return hookState{
		value:        cfg.GetString(profileTestKey),
		token:        cfg.GetString(configuration.AUTHENTICATION_TOKEN),
		networkToken: netCfg.GetString(configuration.AUTHENTICATION_TOKEN),
		sameConfig:   netCfg == cfg,
	}
}

// newProfileBase returns a configuration whose values come from a snyk.json file in dir and that has no profile base
// directory, so profiles are read from the default storage directory unless the caller sets profile.BaseDirKey.
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
	base := newProfileBase(dir)
	base.Set(profile.BaseDirKey, dir)
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

// writeProfileFile writes the profile name, holding the value of profileTestKey, to baseDir/profiles/name.json.
func writeProfileFile(t *testing.T, baseDir, name, value string) {
	t.Helper()
	dir := filepath.Join(baseDir, "profiles")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	content := fmt.Sprintf(`{%q:%q}`, profileTestKey, value)
	require.NoError(t, os.WriteFile(filepath.Join(dir, name+".json"), []byte(content), 0o600))
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
		wantMsg      string
		fix          func(env *profileEnv) // optional: fixing the cause lets the same selection succeed
		wantAfterFix string
	}{
		{name: "unknown_profile_fails_the_invocation", setup: func(env *profileEnv) { env.selectProfile("missing") }, wantErr: profile.ErrNotFound},
		{name: "name_with_a_path_separator_is_rejected", setup: func(env *profileEnv) { env.selectProfile("../escape") }, wantErr: profile.ErrInvalidName},
		{name: "name_with_a_space_is_rejected", setup: func(env *profileEnv) { env.selectProfile("Bad Name") }, wantErr: profile.ErrInvalidName},
		{
			name:    "nil_profile_fails_the_invocation",
			setup:   func(env *profileEnv) { env.impl().profiles = nilProfileRegistry{}; env.selectProfile("anything") },
			wantErr: errProfileWithoutConfig,
		},
		{
			name:    "profile_without_configuration_fails_the_invocation",
			setup:   func(env *profileEnv) { env.impl().profiles = nilConfigRegistry{}; env.selectProfile("machine") },
			wantErr: errProfileWithoutConfig,
		},
		{
			name: "relative_base_dir_fails_the_selection_and_is_retried_after_the_fix",
			setup: func(env *profileEnv) {
				env.base.Set(profile.BaseDirKey, "relative-profiles")
				env.selectProfile("machine")
			},
			wantMsg:      "must be absolute",
			fix:          func(env *profileEnv) { env.base.Set(profile.BaseDirKey, env.dir) },
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

			if tc.fix != nil {
				tc.fix(env)
				output, err = env.engine.Invoke(NewWorkflowIdentifier("leaf"))
				assert.Equal(t, tc.wantAfterFix, report(t, output, err), "the failure must not be cached")
			}
		})
	}
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
// profile base directory nor builds a registry.
func Test_Engine_Profile_NoRegistryIsBuiltForTheDefaultProfile(t *testing.T) {
	base := newProfileBase(t.TempDir())
	var baseDirReads atomic.Int32
	base.AddDefaultValue(profile.BaseDirKey, func(_ configuration.Configuration, existing interface{}) (interface{}, error) {
		baseDirReads.Add(1)
		return existing, nil
	})
	env := newProfileEnvWithBase(t, t.TempDir(), base)

	for _, name := range []string{"", profile.DefaultName} {
		env.selectProfile(name)
		output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
		assert.Equal(t, defaultPayload, report(t, output, err), "profile %q", name)
	}
	assert.Equal(t, int32(0), baseDirReads.Load(), "the default profile must not read the profile base directory")
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
	assert.Equal(t, "machine-value", env.hookState.value)
	assert.True(t, env.hookState.sameConfig, "the hook network access must be bound to the hook configuration")
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

	configB := newProfileBase(env.dir)
	configB.Set(profile.BaseDirKey, env.dir)
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

// Test_Engine_Profile_DefaultStorageDirIsUsedWithoutBaseDirKey checks that without a profile base directory the profiles
// are read from the default storage directory.
func Test_Engine_Profile_DefaultStorageDirIsUsedWithoutBaseDirKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	dir := t.TempDir()
	env := newProfileEnvWithBase(t, dir, newProfileBase(dir))
	writeProfileFile(t, filepath.Join(home, ".config", "configstore"), "x", "stored-value")
	env.selectProfile("x")

	output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assert.Equal(t, "stored-value|stored-value|stored-value|", report(t, output, err))
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
	assert.Nil(t, registry)
}

// Test_GetProfileRegistry_FailsForARelativeBaseDirAndKeepsNoFailure checks that a relative base directory is an error,
// and that the failure is not kept once the base directory is fixed.
func Test_GetProfileRegistry_FailsForARelativeBaseDirAndKeepsNoFailure(t *testing.T) {
	env := newProfileEnv(t)
	env.base.Set(profile.BaseDirKey, "relative-profiles")

	registry, err := GetProfileRegistry(env.engine)
	require.Error(t, err)
	assert.ErrorContains(t, err, "must be absolute")
	assert.Nil(t, registry)

	env.base.Set(profile.BaseDirKey, env.dir)
	registry, err = GetProfileRegistry(env.engine)
	require.NoError(t, err)
	assert.NotNil(t, registry, "the failure must not be cached")
}
