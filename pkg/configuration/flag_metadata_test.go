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

// FC-030: AddFlagSet indexes annotations into scopeIndex and remoteKeyIndex
func Test_FC030_AddFlagSet_IndexesAnnotations(t *testing.T) {
	conf := NewInMemory()
	ev, ok := conf.(*extendedViper)
	require.True(t, ok)

	fs := newFlagSetWithAnnotations()
	err := conf.AddFlagSet(fs)
	require.NoError(t, err)

	// scopeIndex: "org" -> ["snyk_code_enabled"], "machine" -> ["api_endpoint"], "folder" -> ["reference_branch"]
	assert.ElementsMatch(t, []string{"snyk_code_enabled"}, ev.scopeIndex["org"])
	assert.ElementsMatch(t, []string{"api_endpoint"}, ev.scopeIndex["machine"])
	assert.ElementsMatch(t, []string{"reference_branch"}, ev.scopeIndex["folder"])

	// remoteKeyIndex: "snyk_code_enabled" -> "snyk_code_enabled", "api_endpoint" -> "api_endpoint"
	assert.Equal(t, "snyk_code_enabled", ev.remoteKeyIndex["snyk_code_enabled"])
	assert.Equal(t, "api_endpoint", ev.remoteKeyIndex["api_endpoint"])
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

// FC-038: ConfigResolver.Resolve machine scope precedence
func Test_FC038_Resolve_MachineScope(t *testing.T) {
	conf := NewInMemory()
	fm, ok := conf.(FlagMetadata)
	require.True(t, ok)

	fs := newFlagSetWithAnnotations()
	err := conf.AddFlagSet(fs)
	require.NoError(t, err)

	resolver := NewConfigResolver(conf)
	const name = "api_endpoint"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	// 5. default
	val, src := resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, ConfigSourceDefault, src)
	assert.Equal(t, "", val)

	// 4. remote (regular)
	conf.Set(RemoteOrgKey(orgID, name), &RemoteConfigField{Value: "https://remote.example.com"})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, ConfigSourceRemote, src)
	assert.Equal(t, "https://remote.example.com", val)

	// 2. user global beats regular remote
	conf.Set(UserGlobalKey(name), "https://user.example.com")
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, ConfigSourceUserGlobal, src)
	assert.Equal(t, "https://user.example.com", val)

	// 3. enforced remote: on sync user global is cleared; enforced remote applies when user hasn't set value
	conf.Unset(UserGlobalKey(name))
	conf.Set(RemoteOrgKey(orgID, name), &RemoteConfigField{Value: "https://enforced.example.com", IsEnforced: true})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, ConfigSourceRemoteEnforced, src)
	assert.Equal(t, "https://enforced.example.com", val)

	// 2. user global also beats enforced remote (set between syncs)
	conf.Set(UserGlobalKey(name), "https://user-override.example.com")
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, ConfigSourceUserGlobal, src)
	assert.Equal(t, "https://user-override.example.com", val)

	// 1. locked remote beats everything including user global
	conf.Set(RemoteOrgKey(orgID, name), &RemoteConfigField{Value: "https://locked.example.com", IsLocked: true})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, ConfigSourceRemoteLocked, src)
	assert.Equal(t, "https://locked.example.com", val)

	_ = fm // used via AddFlagSet
}

// FC-039: ConfigResolver.Resolve org scope precedence
func Test_FC039_Resolve_OrgScope(t *testing.T) {
	conf := NewInMemory()
	fs := newFlagSetWithAnnotations()
	err := conf.AddFlagSet(fs)
	require.NoError(t, err)

	resolver := NewConfigResolver(conf)
	const name = "snyk_code_enabled"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	// 6. default
	val, src := resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, ConfigSourceDefault, src)
	assert.Equal(t, false, val)

	// 5. remote (regular)
	conf.Set(RemoteOrgKey(orgID, name), &RemoteConfigField{Value: true})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, ConfigSourceRemote, src)
	assert.Equal(t, true, val)

	// 4. user global
	conf.Set(UserGlobalKey(name), true)
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, ConfigSourceUserGlobal, src)

	// 2. folder override beats user global
	conf.Set(UserFolderKey(folderPath, name), &LocalConfigField{Value: false, Changed: true})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, ConfigSourceUserOverride, src)
	assert.Equal(t, false, val)

	// 3. enforced remote: user override cleared on sync; without override, enforced applies
	conf.Unset(UserFolderKey(folderPath, name))
	conf.Unset(UserGlobalKey(name))
	conf.Set(RemoteOrgKey(orgID, name), &RemoteConfigField{Value: true, IsEnforced: true})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, ConfigSourceRemoteEnforced, src)
	assert.Equal(t, true, val)

	// 1. locked remote wins over everything
	conf.Set(RemoteOrgKey(orgID, name), &RemoteConfigField{Value: false, IsLocked: true})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, ConfigSourceRemoteLocked, src)
	assert.Equal(t, false, val)
}

// FC-040: ConfigResolver.Resolve folder scope
func Test_FC040_Resolve_FolderScope(t *testing.T) {
	conf := NewInMemory()
	fs := newFlagSetWithAnnotations()
	err := conf.AddFlagSet(fs)
	require.NoError(t, err)

	resolver := NewConfigResolver(conf)
	const name = "reference_branch"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	// default when not set
	val, src := resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, ConfigSourceDefault, src)
	assert.Equal(t, "", val)

	// folder value from user:folder:<path>:<name>
	conf.Set(UserFolderKey(folderPath, name), &LocalConfigField{Value: "main", Changed: true})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, ConfigSourceFolder, src)
	assert.Equal(t, "main", val)
}

// FC-041: ConfigResolver is stateless — different org returns different remote config
func Test_FC041_Resolve_Stateless_OrgParameter(t *testing.T) {
	conf := NewInMemory()
	fs := newFlagSetWithAnnotations()
	err := conf.AddFlagSet(fs)
	require.NoError(t, err)

	resolver := NewConfigResolver(conf)
	const name = "snyk_code_enabled"
	const folderPath = "/workspace/project"

	conf.Set(RemoteOrgKey("org-A", name), &RemoteConfigField{Value: true})
	conf.Set(RemoteOrgKey("org-B", name), &RemoteConfigField{Value: false})

	valA, _ := resolver.Resolve(name, "org-A", folderPath)
	valB, _ := resolver.Resolve(name, "org-B", folderPath)

	assert.Equal(t, true, valA)
	assert.Equal(t, false, valB)
}

// FC-042: IsLocked reads RemoteConfigField.IsLocked from RemoteOrgKey
func Test_FC042_IsLocked_ReadsRemote(t *testing.T) {
	conf := NewInMemory()
	fs := newFlagSetWithAnnotations()
	err := conf.AddFlagSet(fs)
	require.NoError(t, err)

	resolver := NewConfigResolver(conf)
	const name = "snyk_code_enabled"
	const orgID = "org123"

	assert.False(t, resolver.IsLocked(name, orgID))

	conf.Set(RemoteOrgKey(orgID, name), &RemoteConfigField{Value: true, IsLocked: true})
	assert.True(t, resolver.IsLocked(name, orgID))
}

// FC-043: IsEnforced reads RemoteConfigField.IsEnforced from RemoteOrgKey
func Test_FC043_IsEnforced_ReadsRemote(t *testing.T) {
	conf := NewInMemory()
	fs := newFlagSetWithAnnotations()
	err := conf.AddFlagSet(fs)
	require.NoError(t, err)

	resolver := NewConfigResolver(conf)
	const name = "snyk_code_enabled"
	const orgID = "org123"

	assert.False(t, resolver.IsEnforced(name, orgID))

	conf.Set(RemoteOrgKey(orgID, name), &RemoteConfigField{Value: true, IsEnforced: true})
	assert.True(t, resolver.IsEnforced(name, orgID))
}

// FC-044: LocalConfigField with Changed: false is NOT an active override
func Test_FC044_LocalConfigField_ChangedRequired(t *testing.T) {
	conf := NewInMemory()
	fs := newFlagSetWithAnnotations()
	err := conf.AddFlagSet(fs)
	require.NoError(t, err)

	resolver := NewConfigResolver(conf)
	const name = "snyk_code_enabled"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	// Changed: false — should NOT override; default applies
	conf.Set(UserFolderKey(folderPath, name), &LocalConfigField{Value: true, Changed: false})
	_, src := resolver.Resolve(name, orgID, folderPath)
	assert.NotEqual(t, ConfigSourceUserOverride, src, "Changed:false override must not apply")
}

// FC-045: Resolver reads folder overrides from user:folder:<folderPath>:<name> keys
func Test_FC045_Resolver_FolderOverride_FromPrefixKeys(t *testing.T) {
	conf := NewInMemory()
	fs := newFlagSetWithAnnotations()
	err := conf.AddFlagSet(fs)
	require.NoError(t, err)

	resolver := NewConfigResolver(conf)
	const name = "snyk_code_enabled"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	conf.Set(UserFolderKey(folderPath, name), &LocalConfigField{Value: true, Changed: true})

	val, src := resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, ConfigSourceUserOverride, src)
	assert.Equal(t, true, val)
}

// Test_ClonePreservesFlagMetadata verifies that Clone() preserves flag metadata indexes.
// Clone iterates stored flagsets and calls AddFlagSet on each, which re-indexes annotations.
func Test_ClonePreservesFlagMetadata(t *testing.T) {
	conf := NewInMemory()
	fs := newFlagSetWithAnnotations()
	err := conf.AddFlagSet(fs)
	require.NoError(t, err)

	clone := conf.Clone()
	fm, ok := clone.(FlagMetadata)
	require.True(t, ok, "Clone must implement FlagMetadata")

	// Verify FlagMetadata methods work on the clone
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

	// ConfigResolver on clone should resolve correctly
	resolver := NewConfigResolver(clone)
	valResolved, src := resolver.Resolve("snyk_code_enabled", "org123", "/workspace/project")
	assert.Equal(t, ConfigSourceDefault, src)
	assert.Equal(t, false, valResolved)
}
