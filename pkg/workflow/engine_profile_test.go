package workflow

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/profile"
)

const (
	profileTestKey     = "testkey"
	profileTestOnlyKey = "onlydefault"
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
}

// newProfileEnv returns an initialized engine. Its "leaf" workflow reports
// "config|engineConfig|networkConfig|onlyKey" for the configurations it sees. The engine has a profile
// registry only when withRegistry is set.
func newProfileEnv(t *testing.T, withRegistry bool) *profileEnv {
	t.Helper()
	dir := t.TempDir()
	base := configuration.NewWithOpts(
		configuration.WithFiles(filepath.Join(dir, "snyk.json")),
		configuration.WithCachingEnabled(configuration.NoCacheExpiration),
	)
	base.Set(profileTestKey, "default-value")
	base.Set(profileTestOnlyKey, "only-default")

	env := &profileEnv{t: t, dir: dir, base: base, engine: NewWorkFlowEngine(base)}
	if withRegistry {
		reg, err := profile.NewFileRegistry(dir, base)
		require.NoError(t, err)
		require.NoError(t, SetProfileRegistry(env.engine, reg))
	}

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

	require.NoError(t, AddPostInvokeHook(env.engine, func(_ context.Context, e Engine, result InvokeOutput) {
		env.hookMu.Lock()
		defer env.hookMu.Unlock()
		env.hookErr = result.GetError()
		env.hookValue = e.GetConfiguration().GetString(profileTestKey)
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

func Test_SetProfileRegistry_UnsupportedEngine(t *testing.T) {
	env := newProfileEnv(t, false)
	err := SetProfileRegistry(&engineWrapper{WrappedEngine: env.engine}, nil)
	assert.Error(t, err)
}

type nilProfileRegistry struct{}

//nolint:nilnil // the registry breaks its contract on purpose: the engine must fail the invocation, not run it
func (nilProfileRegistry) Profile(string) (profile.Profile, error) { return nil, nil }

func Test_Engine_Profile_NilProfileFailsInvocation(t *testing.T) {
	env := newProfileEnv(t, false)
	require.NoError(t, SetProfileRegistry(env.engine, nilProfileRegistry{}))
	env.selectProfile("anything")

	_, err := env.engine.Invoke(NewWorkflowIdentifier("leaf"))
	assert.Error(t, err)
	assert.Equal(t, 0, env.leafRuns())
}
