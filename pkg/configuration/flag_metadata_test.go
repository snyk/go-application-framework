package configuration_test

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func newTestFlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.Bool("snyk_code_enabled", false, "Enable Snyk Code analysis")
	fs.Lookup("snyk_code_enabled").Annotations = map[string][]string{
		"config.scope":       {"org"},
		"config.remoteKey":   {"snyk_code_enabled"},
		"config.displayName": {"Snyk Code"},
		"config.description": {"Enable Snyk Code security analysis"},
		"config.ideKey":      {"activateSnykCode"},
	}

	fs.String("api_endpoint", "", "API endpoint URL")
	fs.Lookup("api_endpoint").Annotations = map[string][]string{
		"config.scope":       {"machine"},
		"config.remoteKey":   {"api_endpoint"},
		"config.displayName": {"API Endpoint"},
		"config.description": {"Snyk API endpoint URL"},
		"config.ideKey":      {"endpoint"},
	}

	fs.String("reference_branch", "", "Reference branch for delta findings")
	fs.Lookup("reference_branch").Annotations = map[string][]string{
		"config.scope":       {"folder"},
		"config.displayName": {"Reference Branch"},
		"config.description": {"Branch used as baseline for net-new findings"},
	}

	return fs
}

func Test_AddFlagSet_FlagsResolvable(t *testing.T) {
	conf := configuration.NewInMemory()
	fm, ok := conf.(workflow.FlagMetadata)
	require.True(t, ok)

	require.NoError(t, conf.AddFlagSet(newTestFlagSet()))

	assert.ElementsMatch(t, []string{"snyk_code_enabled"}, fm.FlagsByAnnotation("config.scope", "org"))
	assert.ElementsMatch(t, []string{"api_endpoint"}, fm.FlagsByAnnotation("config.scope", "machine"))
	assert.ElementsMatch(t, []string{"reference_branch"}, fm.FlagsByAnnotation("config.scope", "folder"))

	name, found := fm.FlagNameByAnnotation("config.remoteKey", "snyk_code_enabled")
	assert.True(t, found)
	assert.Equal(t, "snyk_code_enabled", name)

	name, found = fm.FlagNameByAnnotation("config.remoteKey", "api_endpoint")
	assert.True(t, found)
	assert.Equal(t, "api_endpoint", name)
}

func Test_GetFlagAnnotation(t *testing.T) {
	conf := configuration.NewInMemory()
	fm, ok := conf.(workflow.FlagMetadata)
	require.True(t, ok)

	require.NoError(t, conf.AddFlagSet(newTestFlagSet()))

	val, found := fm.GetFlagAnnotation("snyk_code_enabled", "config.scope")
	assert.True(t, found)
	assert.Equal(t, "org", val)

	val, found = fm.GetFlagAnnotation("api_endpoint", "config.remoteKey")
	assert.True(t, found)
	assert.Equal(t, "api_endpoint", val)

	_, found = fm.GetFlagAnnotation("nonexistent_flag", "config.scope")
	assert.False(t, found)
}

func Test_FlagsByAnnotation_Scope(t *testing.T) {
	conf := configuration.NewInMemory()
	fm, ok := conf.(workflow.FlagMetadata)
	require.True(t, ok)

	require.NoError(t, conf.AddFlagSet(newTestFlagSet()))

	assert.ElementsMatch(t, []string{"snyk_code_enabled"}, fm.FlagsByAnnotation("config.scope", "org"))
	assert.ElementsMatch(t, []string{"api_endpoint"}, fm.FlagsByAnnotation("config.scope", "machine"))
	assert.ElementsMatch(t, []string{"reference_branch"}, fm.FlagsByAnnotation("config.scope", "folder"))
	assert.Empty(t, fm.FlagsByAnnotation("config.scope", "nonexistent"))
}

func Test_FlagNameByAnnotation_RemoteKey(t *testing.T) {
	conf := configuration.NewInMemory()
	fm, ok := conf.(workflow.FlagMetadata)
	require.True(t, ok)

	require.NoError(t, conf.AddFlagSet(newTestFlagSet()))

	name, found := fm.FlagNameByAnnotation("config.remoteKey", "snyk_code_enabled")
	assert.True(t, found)
	assert.Equal(t, "snyk_code_enabled", name)

	name, found = fm.FlagNameByAnnotation("config.remoteKey", "api_endpoint")
	assert.True(t, found)
	assert.Equal(t, "api_endpoint", name)

	_, found = fm.FlagNameByAnnotation("config.remoteKey", "no_such_key")
	assert.False(t, found)
}

func Test_GetFlagType_And_Usage(t *testing.T) {
	conf := configuration.NewInMemory()
	fm, ok := conf.(workflow.FlagMetadata)
	require.True(t, ok)

	require.NoError(t, conf.AddFlagSet(newTestFlagSet()))

	assert.Equal(t, "bool", fm.GetFlagType("snyk_code_enabled"))
	assert.Equal(t, "string", fm.GetFlagType("api_endpoint"))
	assert.Equal(t, "", fm.GetFlagType("nonexistent_flag"))

	assert.Equal(t, "Enable Snyk Code analysis", fm.GetFlagUsage("snyk_code_enabled"))
	assert.Equal(t, "API endpoint URL", fm.GetFlagUsage("api_endpoint"))
	assert.Equal(t, "", fm.GetFlagUsage("nonexistent_flag"))
}

func Test_ClonePreservesFlagMetadata(t *testing.T) {
	conf := configuration.NewInMemory()
	require.NoError(t, conf.AddFlagSet(newTestFlagSet()))

	clone := conf.Clone()
	fm, ok := clone.(workflow.FlagMetadata)
	require.True(t, ok, "Clone must implement FlagMetadata")

	val, found := fm.GetFlagAnnotation("snyk_code_enabled", "config.scope")
	assert.True(t, found)
	assert.Equal(t, "org", val)

	orgFlags := fm.FlagsByAnnotation("config.scope", "org")
	assert.ElementsMatch(t, []string{"snyk_code_enabled"}, orgFlags)

	name, found := fm.FlagNameByAnnotation("config.remoteKey", "api_endpoint")
	assert.True(t, found)
	assert.Equal(t, "api_endpoint", name)

	assert.Equal(t, "bool", fm.GetFlagType("snyk_code_enabled"))
	assert.Equal(t, "Enable Snyk Code analysis", fm.GetFlagUsage("snyk_code_enabled"))
}
