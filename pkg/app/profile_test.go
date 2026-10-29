package app

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/profile"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_WithProfileRegistry_RunsInvocationOnSelectedProfile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	base := configuration.NewWithOpts(configuration.WithFiles(filepath.Join(dir, "snyk.json")))
	registry, err := profile.NewFileRegistry(dir, base)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "profiles"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "profiles", "work.json"), []byte(`{"marker":"from-work"}`), 0o600))

	engine := CreateAppEngineWithOptions(
		WithConfiguration(base),
		WithLogger(log.New(io.Discard, "", 0)),
		WithProfileRegistry(registry),
	)

	id := workflow.NewWorkflowIdentifier("profile.test")
	var observed string
	_, err = engine.Register(id, workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("t", pflag.ContinueOnError)),
		func(ictx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
			observed = ictx.GetConfiguration().GetString("marker")
			return nil, nil
		})
	require.NoError(t, err)
	require.NoError(t, engine.Init())

	base.Set(profile.ConfigKey, "work")
	_, err = engine.Invoke(id)
	require.NoError(t, err)
	assert.Equal(t, "from-work", observed)
}

func Test_WithProfileRegistry_FailedSelectionFailsTheInvocation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	base := configuration.NewWithOpts(configuration.WithFiles(filepath.Join(dir, "snyk.json")))
	registry, err := profile.NewFileRegistry(dir, base)
	require.NoError(t, err)

	engine := CreateAppEngineWithOptions(
		WithConfiguration(base),
		WithLogger(log.New(io.Discard, "", 0)),
		WithProfileRegistry(registry),
	)

	id := workflow.NewWorkflowIdentifier("profile.failed")
	ran := false
	_, err = engine.Register(id, workflow.ConfigurationOptionsFromFlagset(pflag.NewFlagSet("t", pflag.ContinueOnError)),
		func(_ workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
			ran = true
			return nil, nil
		})
	require.NoError(t, err)
	require.NoError(t, engine.Init())

	base.Set(profile.ConfigKey, "missing")
	_, err = engine.Invoke(id)
	assert.ErrorIs(t, err, profile.ErrNotFound)
	assert.False(t, ran, "the workflow must not run on a profile that does not exist")
}
