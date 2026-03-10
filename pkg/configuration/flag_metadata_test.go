package configuration

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FC-035: UserGlobalKey prefix helper
func Test_FC035_UserGlobalKey(t *testing.T) {
	assert.Equal(t, "user:global:snyk_code_enabled", UserGlobalKey("snyk_code_enabled"))
}

// FC-036: UserFolderKey prefix helper
func Test_FC036_UserFolderKey(t *testing.T) {
	assert.Equal(t, "user:folder:/path/to/folder:snyk_code_enabled", UserFolderKey("/path/to/folder", "snyk_code_enabled"))
}

// FC-037: RemoteOrgKey prefix helper
func Test_FC037_RemoteOrgKey(t *testing.T) {
	assert.Equal(t, "remote:org123:snyk_code_enabled", RemoteOrgKey("org123", "snyk_code_enabled"))
}

// FC-037a: RemoteMachineKey prefix helper
func Test_FC037a_RemoteMachineKey(t *testing.T) {
	assert.Equal(t, "remote:machine:api_endpoint", RemoteMachineKey("api_endpoint"))
}

// FC-037b: RemoteOrgFolderKey prefix helper
func Test_FC037b_RemoteOrgFolderKey(t *testing.T) {
	assert.Equal(t, "remote:org123:folder:/path:snyk_code_enabled", RemoteOrgFolderKey("org123", "/path", "snyk_code_enabled"))
}

// FC-037c: FolderMetadataKey prefix helper
func Test_FC037c_FolderMetadataKey(t *testing.T) {
	assert.Equal(t, "folder:/path:preferred_org", FolderMetadataKey("/path", "preferred_org"))
}

// newFlagSetWithAnnotations creates a test flagset with annotated flags.
func newFlagSetWithAnnotations() *pflag.FlagSet {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.Bool("snyk_code_enabled", false, "Enable Snyk Code analysis")
	fs.Lookup("snyk_code_enabled").Annotations = map[string][]string{
		AnnotationScope:       {"org"},
		AnnotationRemoteKey:   {"snyk_code_enabled"},
		AnnotationDisplayName: {"Snyk Code"},
		AnnotationDescription: {"Enable Snyk Code security analysis"},
		AnnotationIdeKey:      {"activateSnykCode"},
	}

	fs.String("api_endpoint", "", "API endpoint URL")
	fs.Lookup("api_endpoint").Annotations = map[string][]string{
		AnnotationScope:       {"machine"},
		AnnotationRemoteKey:   {"api_endpoint"},
		AnnotationDisplayName: {"API Endpoint"},
		AnnotationDescription: {"Snyk API endpoint URL"},
		AnnotationIdeKey:      {"endpoint"},
	}

	fs.String("reference_branch", "", "Reference branch for delta findings")
	fs.Lookup("reference_branch").Annotations = map[string][]string{
		AnnotationScope:       {"folder"},
		AnnotationDisplayName: {"Reference Branch"},
		AnnotationDescription: {"Branch used as baseline for net-new findings"},
	}

	return fs
}

// FC-030: FlagsByAnnotation and FlagNameByAnnotation resolve correctly after AddFlagSet
func Test_FC030_AddFlagSet_FlagsResolvable(t *testing.T) {
	conf := NewInMemory()
	fm, ok := conf.(FlagMetadata)
	require.True(t, ok)

	fs := newFlagSetWithAnnotations()
	require.NoError(t, conf.AddFlagSet(fs))

	assert.ElementsMatch(t, []string{"snyk_code_enabled"}, fm.FlagsByAnnotation(AnnotationScope, "org"))
	assert.ElementsMatch(t, []string{"api_endpoint"}, fm.FlagsByAnnotation(AnnotationScope, "machine"))
	assert.ElementsMatch(t, []string{"reference_branch"}, fm.FlagsByAnnotation(AnnotationScope, "folder"))

	name, found := fm.FlagNameByAnnotation(AnnotationRemoteKey, "snyk_code_enabled")
	assert.True(t, found)
	assert.Equal(t, "snyk_code_enabled", name)

	name, found = fm.FlagNameByAnnotation(AnnotationRemoteKey, "api_endpoint")
	assert.True(t, found)
	assert.Equal(t, "api_endpoint", name)
}

// FC-031: GetFlagAnnotation returns correct annotation value
func Test_FC031_GetFlagAnnotation(t *testing.T) {
	conf := NewInMemory()
	fm, ok := conf.(FlagMetadata)
	require.True(t, ok, "Configuration must implement FlagMetadata")

	fs := newFlagSetWithAnnotations()
	err := conf.AddFlagSet(fs)
	require.NoError(t, err)

	val, found := fm.GetFlagAnnotation("snyk_code_enabled", AnnotationScope)
	assert.True(t, found)
	assert.Equal(t, "org", val)

	val, found = fm.GetFlagAnnotation("api_endpoint", AnnotationRemoteKey)
	assert.True(t, found)
	assert.Equal(t, "api_endpoint", val)

	_, found = fm.GetFlagAnnotation("nonexistent_flag", AnnotationScope)
	assert.False(t, found)
}

// FC-032: FlagsByAnnotation returns all flags matching annotation value
func Test_FC032_FlagsByAnnotation_Scope(t *testing.T) {
	conf := NewInMemory()
	fm, ok := conf.(FlagMetadata)
	require.True(t, ok)

	fs := newFlagSetWithAnnotations()
	err := conf.AddFlagSet(fs)
	require.NoError(t, err)

	orgFlags := fm.FlagsByAnnotation(AnnotationScope, "org")
	assert.ElementsMatch(t, []string{"snyk_code_enabled"}, orgFlags)

	machineFlags := fm.FlagsByAnnotation(AnnotationScope, "machine")
	assert.ElementsMatch(t, []string{"api_endpoint"}, machineFlags)

	folderFlags := fm.FlagsByAnnotation(AnnotationScope, "folder")
	assert.ElementsMatch(t, []string{"reference_branch"}, folderFlags)

	noFlags := fm.FlagsByAnnotation(AnnotationScope, "nonexistent")
	assert.Empty(t, noFlags)
}

// FC-033: FlagNameByAnnotation returns flag name by remote key annotation value
func Test_FC033_FlagNameByAnnotation_RemoteKey(t *testing.T) {
	conf := NewInMemory()
	fm, ok := conf.(FlagMetadata)
	require.True(t, ok)

	fs := newFlagSetWithAnnotations()
	err := conf.AddFlagSet(fs)
	require.NoError(t, err)

	name, found := fm.FlagNameByAnnotation(AnnotationRemoteKey, "snyk_code_enabled")
	assert.True(t, found)
	assert.Equal(t, "snyk_code_enabled", name)

	name, found = fm.FlagNameByAnnotation(AnnotationRemoteKey, "api_endpoint")
	assert.True(t, found)
	assert.Equal(t, "api_endpoint", name)

	_, found = fm.FlagNameByAnnotation(AnnotationRemoteKey, "no_such_key")
	assert.False(t, found)
}

// FC-034: GetFlagType and GetFlagUsage return pflag-derived values
func Test_FC034_GetFlagType_And_Usage(t *testing.T) {
	conf := NewInMemory()
	fm, ok := conf.(FlagMetadata)
	require.True(t, ok)

	fs := newFlagSetWithAnnotations()
	err := conf.AddFlagSet(fs)
	require.NoError(t, err)

	assert.Equal(t, "bool", fm.GetFlagType("snyk_code_enabled"))
	assert.Equal(t, "string", fm.GetFlagType("api_endpoint"))
	assert.Equal(t, "", fm.GetFlagType("nonexistent_flag"))

	assert.Equal(t, "Enable Snyk Code analysis", fm.GetFlagUsage("snyk_code_enabled"))
	assert.Equal(t, "API endpoint URL", fm.GetFlagUsage("api_endpoint"))
	assert.Equal(t, "", fm.GetFlagUsage("nonexistent_flag"))
}

// Test_ClonePreservesFlagMetadata verifies that Clone() preserves flag metadata.
func Test_ClonePreservesFlagMetadata(t *testing.T) {
	conf := NewInMemory()
	fs := newFlagSetWithAnnotations()
	err := conf.AddFlagSet(fs)
	require.NoError(t, err)

	clone := conf.Clone()
	fm, ok := clone.(FlagMetadata)
	require.True(t, ok, "Clone must implement FlagMetadata")

	val, found := fm.GetFlagAnnotation("snyk_code_enabled", AnnotationScope)
	assert.True(t, found)
	assert.Equal(t, "org", val)

	orgFlags := fm.FlagsByAnnotation(AnnotationScope, "org")
	assert.ElementsMatch(t, []string{"snyk_code_enabled"}, orgFlags)

	name, found := fm.FlagNameByAnnotation(AnnotationRemoteKey, "api_endpoint")
	assert.True(t, found)
	assert.Equal(t, "api_endpoint", name)

	assert.Equal(t, "bool", fm.GetFlagType("snyk_code_enabled"))
	assert.Equal(t, "Enable Snyk Code analysis", fm.GetFlagUsage("snyk_code_enabled"))
}
