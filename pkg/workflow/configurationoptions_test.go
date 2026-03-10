package workflow_test

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func newTestConfigOpts() workflow.ConfigurationOptions {
	return workflow.ConfigurationOptionsFromFlagset(newTestFlagSet())
}

func TestNewConfigurationOptionsStore(t *testing.T) {
	fm := workflow.NewConfigurationOptionsStore(newTestConfigOpts())

	assert.ElementsMatch(t, []string{"snyk_code_enabled"}, fm.FlagsByAnnotation("config.scope", "org"))
	assert.ElementsMatch(t, []string{"api_endpoint"}, fm.FlagsByAnnotation("config.scope", "machine"))
	assert.ElementsMatch(t, []string{"reference_branch"}, fm.FlagsByAnnotation("config.scope", "folder"))
}

func TestAdd(t *testing.T) {
	fm := workflow.NewConfigurationOptionsStore()

	fm.Add(newTestConfigOpts())

	name, found := fm.FlagNameByAnnotation("config.remoteKey", "snyk_code_enabled")
	assert.True(t, found)
	assert.Equal(t, "snyk_code_enabled", name)
}

func TestGetFlagAnnotation(t *testing.T) {
	fm := workflow.NewConfigurationOptionsStore(newTestConfigOpts())

	val, found := fm.GetFlagAnnotation("snyk_code_enabled", "config.scope")
	assert.True(t, found)
	assert.Equal(t, "org", val)

	val, found = fm.GetFlagAnnotation("api_endpoint", "config.remoteKey")
	assert.True(t, found)
	assert.Equal(t, "api_endpoint", val)

	_, found = fm.GetFlagAnnotation("nonexistent_flag", "config.scope")
	assert.False(t, found)
}

func TestFlagsByAnnotation_Scope(t *testing.T) {
	fm := workflow.NewConfigurationOptionsStore(newTestConfigOpts())

	assert.ElementsMatch(t, []string{"snyk_code_enabled"}, fm.FlagsByAnnotation("config.scope", "org"))
	assert.ElementsMatch(t, []string{"api_endpoint"}, fm.FlagsByAnnotation("config.scope", "machine"))
	assert.ElementsMatch(t, []string{"reference_branch"}, fm.FlagsByAnnotation("config.scope", "folder"))
	assert.Empty(t, fm.FlagsByAnnotation("config.scope", "nonexistent"))
}

func TestFlagNameByAnnotation_RemoteKey(t *testing.T) {
	fm := workflow.NewConfigurationOptionsStore(newTestConfigOpts())

	name, found := fm.FlagNameByAnnotation("config.remoteKey", "snyk_code_enabled")
	assert.True(t, found)
	assert.Equal(t, "snyk_code_enabled", name)

	name, found = fm.FlagNameByAnnotation("config.remoteKey", "api_endpoint")
	assert.True(t, found)
	assert.Equal(t, "api_endpoint", name)

	_, found = fm.FlagNameByAnnotation("config.remoteKey", "no_such_key")
	assert.False(t, found)
}

func TestGetFlagType_And_Usage(t *testing.T) {
	fm := workflow.NewConfigurationOptionsStore(newTestConfigOpts())

	assert.Equal(t, "bool", fm.GetFlagType("snyk_code_enabled"))
	assert.Equal(t, "string", fm.GetFlagType("api_endpoint"))
	assert.Equal(t, "", fm.GetFlagType("nonexistent_flag"))

	assert.Equal(t, "Enable Snyk Code analysis", fm.GetFlagUsage("snyk_code_enabled"))
	assert.Equal(t, "API endpoint URL", fm.GetFlagUsage("api_endpoint"))
	assert.Equal(t, "", fm.GetFlagUsage("nonexistent_flag"))
}

func TestConfigurationOptionsImpl_ImplementsFlagMetadata(t *testing.T) {
	var opts workflow.ConfigurationOptions = workflow.ConfigurationOptionsFromFlagset(newTestFlagSet())
	var _ workflow.FlagMetadata = opts
	require.True(t, true)
}

func TestConfigurationOptionsStore_ImplementsFlagMetadata(t *testing.T) {
	var _ workflow.FlagMetadata = workflow.NewConfigurationOptionsStore()
	require.True(t, true)
}

func TestStore_LastRegisteredWins_GetFlagAnnotation(t *testing.T) {
	fs1 := pflag.NewFlagSet("first", pflag.ContinueOnError)
	fs1.Bool("shared_flag", false, "first usage")
	fs1.Lookup("shared_flag").Annotations = map[string][]string{"config.scope": {"org"}}

	fs2 := pflag.NewFlagSet("second", pflag.ContinueOnError)
	fs2.Bool("shared_flag", true, "second usage")
	fs2.Lookup("shared_flag").Annotations = map[string][]string{"config.scope": {"machine"}}

	store := workflow.NewConfigurationOptionsStore(
		workflow.ConfigurationOptionsFromFlagset(fs1),
		workflow.ConfigurationOptionsFromFlagset(fs2),
	)

	val, found := store.GetFlagAnnotation("shared_flag", "config.scope")
	assert.True(t, found)
	assert.Equal(t, "machine", val, "last-registered option should win")
}

func TestStore_FlagsByAnnotation_Deduplicates(t *testing.T) {
	opts := newTestConfigOpts()
	store := workflow.NewConfigurationOptionsStore(opts, opts)

	result := store.FlagsByAnnotation("config.scope", "org")
	assert.Equal(t, 1, len(result), "duplicate flag names must be deduplicated")
	assert.Equal(t, "snyk_code_enabled", result[0])
}

func TestStore_FlagsByAnnotation_RespectsLastRegisteredWins(t *testing.T) {
	fs1 := pflag.NewFlagSet("first", pflag.ContinueOnError)
	fs1.Bool("shared_flag", false, "first usage")
	fs1.Lookup("shared_flag").Annotations = map[string][]string{"config.scope": {"org"}}

	fs2 := pflag.NewFlagSet("second", pflag.ContinueOnError)
	fs2.Bool("shared_flag", true, "second usage")
	fs2.Lookup("shared_flag").Annotations = map[string][]string{"config.scope": {"machine"}}

	store := workflow.NewConfigurationOptionsStore(
		workflow.ConfigurationOptionsFromFlagset(fs1),
		workflow.ConfigurationOptionsFromFlagset(fs2),
	)

	assert.NotContains(t, store.FlagsByAnnotation("config.scope", "org"), "shared_flag",
		"flag whose scope was overridden to machine should not appear under org")
	assert.Contains(t, store.FlagsByAnnotation("config.scope", "machine"), "shared_flag",
		"flag should appear under its effective scope")
}

func TestStore_LastRegisteredWins_GetFlagType(t *testing.T) {
	fs1 := pflag.NewFlagSet("first", pflag.ContinueOnError)
	fs1.Bool("shared_flag", false, "first usage")

	fs2 := pflag.NewFlagSet("second", pflag.ContinueOnError)
	fs2.String("shared_flag", "", "second usage")

	store := workflow.NewConfigurationOptionsStore(
		workflow.ConfigurationOptionsFromFlagset(fs1),
		workflow.ConfigurationOptionsFromFlagset(fs2),
	)

	assert.Equal(t, "string", store.GetFlagType("shared_flag"), "last-registered should win")
}

func TestStore_LastRegisteredWins_GetFlagUsage(t *testing.T) {
	fs1 := pflag.NewFlagSet("first", pflag.ContinueOnError)
	fs1.Bool("shared_flag", false, "first usage")

	fs2 := pflag.NewFlagSet("second", pflag.ContinueOnError)
	fs2.Bool("shared_flag", true, "second usage")

	store := workflow.NewConfigurationOptionsStore(
		workflow.ConfigurationOptionsFromFlagset(fs1),
		workflow.ConfigurationOptionsFromFlagset(fs2),
	)

	assert.Equal(t, "second usage", store.GetFlagUsage("shared_flag"), "last-registered should win")
}
