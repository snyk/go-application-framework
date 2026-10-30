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
)

type profileEnv struct {
	t        *testing.T
	dir      string
	base     configuration.Configuration
	engine   Engine
	registry profile.Registry
	leafMu   sync.Mutex
	leafCnt  int

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

// countingConfig counts the reads of profile.ConfigKey.
type countingConfig struct {
	configuration.Configuration
	profileReads atomic.Int32
}

func (c *countingConfig) GetString(key string) string {
	if key == profile.ConfigKey {
		c.profileReads.Add(1)
	}
	return c.Configuration.GetString(key)
}

// newProfileEnv returns an initialized engine. Its "leaf" workflow reports
// "config|engineConfig|networkConfig|onlyKey" for the configurations it sees. The engine has a file-based profile
// registry only when withRegistry is set.
func newProfileEnv(t *testing.T, withRegistry bool) *profileEnv {
	t.Helper()
	return newProfileEnvWith(t, func(dir string, base configuration.Configuration) profile.Registry {
		if !withRegistry {
			return nil
		}
		reg, err := profile.NewFileRegistry(dir, base)
		require.NoError(t, err)
		return reg
	})
}

// newProfileEnvWith returns an initialized engine whose profile registry is made by makeRegistry from the profile
// directory and the base configuration.
func newProfileEnvWith(t *testing.T, makeRegistry func(dir string, base configuration.Configuration) profile.Registry) *profileEnv {
	t.Helper()
	dir := t.TempDir()
	base := configuration.NewWithOpts(
		configuration.WithFiles(filepath.Join(dir, "snyk.json")),
		configuration.WithCachingEnabled(configuration.NoCacheExpiration),
	)
	base.Set(profileTestKey, "default-value")
	base.Set(profileTestOnlyKey, "only-default")

	reg := makeRegistry(dir, base)
	var opts []EngineOption
	if reg != nil {
		opts = append(opts, WithProfileRegistry(reg))
	}
	env := &profileEnv{t: t, dir: dir, base: base, engine: NewWorkFlowEngine(base, opts...), registry: reg}

	register := func(name string, cb Callback) {
		_, err := env.engine.Register(NewWorkflowIdentifier(name), ConfigurationOptionsFromFlagset(pflag.NewFlagSet(name, pflag.ContinueOnError)), cb)
		require.NoError(t, err)
	}
	register("leaf", func(ictx InvocationContext, _ []Data) ([]Data, error) {
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
	register("bound", func(ictx InvocationContext, _ []Data) ([]Data, error) {
		state := "detached"
		if ictx.GetEngine().GetNetworkAccess().GetConfiguration() == ictx.GetEngine().GetConfiguration() {
			state = "bound"
		}
		return []Data{NewData(NewTypeIdentifier(NewWorkflowIdentifier("bound"), "observed"), "text/plain", state)}, nil
	})
	register("outer", func(ictx InvocationContext, _ []Data) ([]Data, error) {
		return ictx.GetEngine().Invoke(NewWorkflowIdentifier("leaf"))
	})
	// scratch reports the scratch key it sees, then sets it on its configuration.
	register("scratch", func(ictx InvocationContext, _ []Data) ([]Data, error) {
		seen := ictx.GetConfiguration().GetString(profileTestScratchKey)
		ictx.GetConfiguration().Set(profileTestScratchKey, "dirty")
		return []Data{NewData(NewTypeIdentifier(NewWorkflowIdentifier("scratch"), "observed"), "text/plain", seen)}, nil
	})
	// switcher selects a profile that does not exist, then invokes the leaf workflow as a nested invocation.
	register("switcher", func(ictx InvocationContext, _ []Data) ([]Data, error) {
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

func (env *profileEnv) writeProfile(name, value string) {
	env.t.Helper()
	dir := filepath.Join(env.dir, "profiles")
	require.NoError(env.t, os.MkdirAll(dir, 0o755))
	content := fmt.Sprintf(`{%q:%q}`, profileTestKey, value)
	require.NoError(env.t, os.WriteFile(filepath.Join(dir, name+".json"), []byte(content), 0o600))
}

func (env *profileEnv) selectProfile(name string) {
	env.base.Set(profile.ConfigKey, name)
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

// Test_Engine_Profile_NetworkAccessIsBoundToTheEngineConfiguration checks that the network access an invocation reaches
// through its engine is bound to the configuration the engine reports, for the default profile and for a selected one.
// The post-invoke hook path binds it that way, so the invocation must too.
func Test_Engine_Profile_NetworkAccessIsBoundToTheEngineConfiguration(t *testing.T) {
	env := newProfileEnv(t, true)
	env.writeProfile("machine", "machine-value")

	for _, name := range []string{"", "machine"} {
		env.selectProfile(name)
		output, err := env.engine.Invoke(NewWorkflowIdentifier("bound"))
		assert.Equal(t, "bound", report(t, output, err), "profile %q", name)
	}
}

func Test_Engine_Profile_RootRunsOnSelectedProfile(t *testing.T) {
	env := newProfileEnv(t, true)
	env.writeProfile("machine", "machine-value")
	env.selectProfile("machine")

	output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	// the profile file holds the value, and the default-only key is not part of the profile
	assert.Equal(t, "machine-value|machine-value|machine-value|", report(t, output, err))
}

func Test_Engine_Profile_EmptyKeyUsesDefault(t *testing.T) {
	env := newProfileEnv(t, true)
	env.writeProfile("machine", "machine-value")

	output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assert.Equal(t, "default-value|default-value|default-value|only-default", report(t, output, err))
}

func Test_Engine_Profile_UnknownProfileFailsInvocation(t *testing.T) {
	env := newProfileEnv(t, true)
	env.selectProfile("missing")

	output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assert.ErrorIs(t, err, profile.ErrNotFound)
	assert.Empty(t, output)
	assert.Equal(t, 0, env.leafRuns(), "the workflow must not run")

	env.hookMu.Lock()
	defer env.hookMu.Unlock()
	assert.ErrorIs(t, env.hookErr, profile.ErrNotFound)
	assert.Empty(t, env.hookValue, "post-invoke hooks must not see the default configuration")
}

// Test_Engine_Profile_FailedSelectionHooksDoNotReadEnvironment checks that the hooks of a failed selection see an
// empty configuration, which does not read the process environment.
func Test_Engine_Profile_FailedSelectionHooksDoNotReadEnvironment(t *testing.T) {
	t.Setenv("SNYK_TOKEN", "token-from-environment")
	env := newProfileEnv(t, true)
	env.selectProfile("missing")

	_, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	require.ErrorIs(t, err, profile.ErrNotFound)

	env.hookMu.Lock()
	defer env.hookMu.Unlock()
	assert.Empty(t, env.hookState.token, "the hook configuration must not read the environment")
	assert.Empty(t, env.hookState.networkToken, "the hook network access must not read the environment")
}

// Test_Engine_Profile_NoRegistryDoesNotReadProfileKey checks that an engine without a registry does not even look up
// the profile key.
func Test_Engine_Profile_NoRegistryDoesNotReadProfileKey(t *testing.T) {
	env := newProfileEnv(t, false)
	counting := &countingConfig{Configuration: env.base}
	env.engine.SetConfiguration(counting)

	output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assert.Equal(t, "default-value|default-value|default-value|only-default", report(t, output, err))
	assert.Equal(t, int32(0), counting.profileReads.Load())
}

func Test_Engine_Profile_InvalidNameFailsInvocation(t *testing.T) {
	env := newProfileEnv(t, true)
	env.selectProfile("../escape")

	_, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assert.ErrorIs(t, err, profile.ErrInvalidName)
	assert.Equal(t, 0, env.leafRuns())
}

func Test_Engine_Profile_NoRegistryKeepsBehavior(t *testing.T) {
	env := newProfileEnv(t, false)
	env.writeProfile("machine", "machine-value")
	env.selectProfile("machine")

	output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assert.Equal(t, "default-value|default-value|default-value|only-default", report(t, output, err))
}

func Test_Engine_Profile_WithConfigSkipsSelection(t *testing.T) {
	env := newProfileEnv(t, true)
	env.selectProfile("missing")
	custom := configuration.NewInMemory()
	custom.Set(profileTestKey, "custom-value")

	output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"), WithConfig(custom))
	assert.Equal(t, "custom-value|default-value|custom-value|", report(t, output, err))
}

func Test_Engine_Profile_NestedInvocationStaysOnParentProfile(t *testing.T) {
	env := newProfileEnv(t, true)
	env.writeProfile("machine", "machine-value")
	env.selectProfile("machine")

	output, err := env.engine.Invoke(NewWorkflowIdentifier("outer"))
	assert.Equal(t, "machine-value|machine-value|machine-value|", report(t, output, err))
}

func Test_Engine_Profile_ProfilesDoNotShareNetworkAccess(t *testing.T) {
	env := newProfileEnv(t, true)
	env.writeProfile("first", "first-value")
	env.writeProfile("second", "second-value")

	env.selectProfile("first")
	output, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assert.Equal(t, "first-value|first-value|first-value|", report(t, output, err))

	env.selectProfile("second")
	output, err = env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assert.Equal(t, "second-value|second-value|second-value|", report(t, output, err))
}

func Test_Engine_Profile_ConcurrentInvocations(t *testing.T) {
	env := newProfileEnv(t, true)
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
		assert.Equal(t, "machine-value|machine-value|machine-value|", reports[i])
	}
}

type nilProfileRegistry struct{}

//nolint:nilnil // the registry breaks its contract on purpose: the engine must fail the invocation, not run it
func (nilProfileRegistry) Profile(string) (profile.Profile, error) { return nil, nil }

func Test_Engine_Profile_NilProfileFailsInvocation(t *testing.T) {
	env := newProfileEnvWith(t, func(string, configuration.Configuration) profile.Registry {
		return nilProfileRegistry{}
	})
	env.selectProfile("anything")

	_, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assert.Error(t, err)
	assert.Equal(t, 0, env.leafRuns())
}

// Test_Engine_Profile_HookNetworkAccessIsBoundToItsConfiguration checks that the network access of the post-invoke hooks is
// bound to the configuration the hooks see, for a selected profile and for a failed selection.
func Test_Engine_Profile_HookNetworkAccessIsBoundToItsConfiguration(t *testing.T) {
	env := newProfileEnv(t, true)
	env.writeProfile("machine", "machine-value")

	tests := []struct {
		profileName string
		wantErr     error
	}{
		{profileName: "machine"},
		{profileName: "missing", wantErr: profile.ErrNotFound},
	}
	for _, tt := range tests {
		env.selectProfile(tt.profileName)
		_, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
		if tt.wantErr != nil {
			require.ErrorIs(t, err, tt.wantErr, "profile %q", tt.profileName)
		} else {
			require.NoError(t, err, "profile %q", tt.profileName)
		}

		env.hookMu.Lock()
		assert.True(t, env.hookState.sameConfig, "profile %q: the hook network access must be bound to the hook configuration", tt.profileName)
		env.hookMu.Unlock()
	}
}

// Test_Engine_Profile_HookSeesSelectedProfile checks that the post-invoke hooks see the configuration of a selected profile.
func Test_Engine_Profile_HookSeesSelectedProfile(t *testing.T) {
	env := newProfileEnv(t, true)
	env.writeProfile("machine", "machine-value")
	env.selectProfile("machine")

	_, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	require.NoError(t, err)

	env.hookMu.Lock()
	defer env.hookMu.Unlock()
	assert.Equal(t, "machine-value", env.hookState.value)
}

// Test_Engine_Profile_InvocationChangesStayInItsConfiguration checks that a change a workflow makes to its configuration
// neither reaches the profile nor the invocations that follow.
func Test_Engine_Profile_InvocationChangesStayInItsConfiguration(t *testing.T) {
	env := newProfileEnv(t, true)
	env.writeProfile("machine", "machine-value")
	env.selectProfile("machine")

	for range 2 {
		output, err := env.engine.Invoke(NewWorkflowIdentifier("scratch"))
		assert.Empty(t, report(t, output, err), "a later invocation must not see the change of an earlier one")
	}

	p, err := env.registry.Profile("machine")
	require.NoError(t, err)
	assert.Empty(t, p.Configuration().GetString(profileTestScratchKey), "the profile must not see the change")
}

// Test_Engine_Profile_NestedInvocationIgnoresLaterSelection checks that a nested invocation keeps the profile of its root
// even when the configuration of the engine selects another one afterwards.
func Test_Engine_Profile_NestedInvocationIgnoresLaterSelection(t *testing.T) {
	env := newProfileEnv(t, true)
	env.writeProfile("machine", "machine-value")
	env.selectProfile("machine")

	output, err := env.engine.Invoke(NewWorkflowIdentifier("switcher"))
	assert.Equal(t, "machine-value|machine-value|machine-value|", report(t, output, err))
}

// nilConfigRegistry finds profiles that have no configuration.
type nilConfigRegistry struct{}

func (nilConfigRegistry) Profile(name string) (profile.Profile, error) {
	return nilConfigProfile{name: name}, nil
}

type nilConfigProfile struct{ name string }

func (p nilConfigProfile) Name() string                             { return p.name }
func (nilConfigProfile) Configuration() configuration.Configuration { return nil }

func Test_Engine_Profile_ProfileWithoutConfigurationFailsInvocation(t *testing.T) {
	env := newProfileEnvWith(t, func(string, configuration.Configuration) profile.Registry {
		return nilConfigRegistry{}
	})
	env.selectProfile("machine")

	_, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	require.Error(t, err)
	assert.ErrorIs(t, err, errProfileWithoutConfig)
	assert.Equal(t, 0, env.leafRuns(), "the workflow must not run")
}
