package configresolver_test

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	cr "github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func newFlagSetWithAnnotations() *pflag.FlagSet {
	fs := pflag.NewFlagSet("test-flags", pflag.ContinueOnError)
	fs.String("api_endpoint", "", "API endpoint URL")
	fs.Lookup("api_endpoint").Annotations = map[string][]string{
		cr.AnnotationScope:       {"machine"},
		cr.AnnotationRemoteKey:   {"api_endpoint"},
		cr.AnnotationDisplayName: {"API Endpoint"},
		cr.AnnotationIdeKey:      {"endpoint"},
	}
	fs.Bool("snyk_code_enabled", false, "Enable Snyk Code analysis")
	fs.Lookup("snyk_code_enabled").Annotations = map[string][]string{
		cr.AnnotationScope:       {"org"},
		cr.AnnotationRemoteKey:   {"snyk_code_enabled"},
		cr.AnnotationDisplayName: {"Snyk Code"},
		cr.AnnotationIdeKey:      {"activateSnykCode"},
	}
	fs.String("reference_branch", "", "Reference branch for delta findings")
	fs.Lookup("reference_branch").Annotations = map[string][]string{
		cr.AnnotationScope:       {"folder"},
		cr.AnnotationDisplayName: {"Reference Branch"},
	}
	return fs
}

func setupConf(t *testing.T) (configuration.Configuration, workflow.FlagMetadata) {
	t.Helper()
	fs := newFlagSetWithAnnotations()
	conf := configuration.NewInMemory()
	require.NoError(t, conf.AddFlagSet(fs))
	fm := workflow.NewFlagMetadata(workflow.ConfigurationOptionsFromFlagset(fs))
	return conf, fm
}

func Test_Resolve_MachineScope_Precedence(t *testing.T) {
	conf, fm := setupConf(t)
	resolver := cr.New(conf, fm)
	const name = "api_endpoint"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	val, src := resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceDefault, src)
	assert.Equal(t, "", val)

	conf.Set(cr.RemoteMachineKey(name), &cr.RemoteConfigField{Value: "https://remote.example.com"})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceRemote, src)
	assert.Equal(t, "https://remote.example.com", val)

	conf.Set(cr.UserGlobalKey(name), "https://user.example.com")
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceUserGlobal, src)
	assert.Equal(t, "https://user.example.com", val)

	conf.Set(cr.RemoteMachineKey(name), &cr.RemoteConfigField{Value: "https://locked.example.com", IsLocked: true})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceRemoteLocked, src)
	assert.Equal(t, "https://locked.example.com", val)
}

func Test_Resolve_OrgScope_Precedence(t *testing.T) {
	conf, fm := setupConf(t)
	resolver := cr.New(conf, fm)
	const name = "snyk_code_enabled"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	val, src := resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceDefault, src)
	assert.Equal(t, false, val)

	conf.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: true})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceRemote, src)
	assert.Equal(t, true, val)

	conf.Set(cr.UserGlobalKey(name), true)
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceUserGlobal, src)
	assert.Equal(t, true, val)

	conf.Set(cr.UserFolderKey(folderPath, name), &cr.LocalConfigField{Value: false, Changed: true})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceUserFolderOverride, src)
	assert.Equal(t, false, val)

	conf.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: false, IsLocked: true})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceRemoteLocked, src)
	assert.Equal(t, false, val)
}

func Test_Resolve_FolderScope(t *testing.T) {
	conf, fm := setupConf(t)
	resolver := cr.New(conf, fm)
	const name = "reference_branch"
	const folderPath = "/workspace/project"

	val, src := resolver.Resolve(name, "", folderPath)
	assert.Equal(t, cr.ConfigSourceDefault, src)
	assert.Equal(t, "", val)

	conf.Set(cr.UserFolderKey(folderPath, name), &cr.LocalConfigField{Value: "main", Changed: true})
	val, src = resolver.Resolve(name, "", folderPath)
	assert.Equal(t, cr.ConfigSourceFolder, src)
	assert.Equal(t, "main", val)
}

func Test_Resolve_Stateless_OrgParameter(t *testing.T) {
	conf, fm := setupConf(t)
	resolver := cr.New(conf, fm)
	const name = "snyk_code_enabled"
	const folderPath = "/workspace/project"

	conf.Set(cr.RemoteOrgKey("org-A", name), &cr.RemoteConfigField{Value: true})
	conf.Set(cr.RemoteOrgKey("org-B", name), &cr.RemoteConfigField{Value: false})

	valA, _ := resolver.Resolve(name, "org-A", folderPath)
	valB, _ := resolver.Resolve(name, "org-B", folderPath)

	assert.Equal(t, true, valA)
	assert.Equal(t, false, valB)
}

func Test_IsLocked_ReadsRemote(t *testing.T) {
	conf, fm := setupConf(t)
	resolver := cr.New(conf, fm)
	const name = "snyk_code_enabled"
	const orgID = "org123"

	assert.False(t, resolver.IsLocked(name, orgID))

	conf.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: true, IsLocked: true})
	assert.True(t, resolver.IsLocked(name, orgID))
}

func Test_LocalConfigField_ChangedRequired(t *testing.T) {
	conf, fm := setupConf(t)
	resolver := cr.New(conf, fm)
	const name = "snyk_code_enabled"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	conf.Set(cr.UserFolderKey(folderPath, name), &cr.LocalConfigField{Value: true, Changed: false})
	_, src := resolver.Resolve(name, orgID, folderPath)
	assert.NotEqual(t, cr.ConfigSourceUserFolderOverride, src, "Changed:false override must not apply")
}

func Test_ResolveBool(t *testing.T) {
	conf, fm := setupConf(t)
	resolver := cr.New(conf, fm)
	const orgID = "org123"
	const folderPath = "/workspace/project"

	assert.False(t, resolver.ResolveBool("snyk_code_enabled", orgID, folderPath))

	conf.Set(cr.UserGlobalKey("snyk_code_enabled"), true)
	assert.True(t, resolver.ResolveBool("snyk_code_enabled", orgID, folderPath))
}

func Test_ResolveMachine_UsesMachineKey(t *testing.T) {
	conf, fm := setupConf(t)
	resolver := cr.New(conf, fm)
	const name = "api_endpoint"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	conf.Set(cr.RemoteMachineKey(name), &cr.RemoteConfigField{Value: "https://machine.example.com"})
	val, src := resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceRemote, src)
	assert.Equal(t, "https://machine.example.com", val)

	conf.Unset(cr.RemoteMachineKey(name))
	conf.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: "https://org.example.com"})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceDefault, src, "org key must not apply to machine-scope setting")
	assert.Equal(t, "", val)
}

func Test_IsLocked_MachineScope(t *testing.T) {
	conf, fm := setupConf(t)
	resolver := cr.New(conf, fm)
	const name = "api_endpoint"

	conf.Set(cr.RemoteMachineKey(name), &cr.RemoteConfigField{Value: "https://locked.example.com", IsLocked: true})
	assert.True(t, resolver.IsLocked(name, "any-org"))
}

func Test_FolderOverride_FromPrefixKeys(t *testing.T) {
	conf, fm := setupConf(t)
	resolver := cr.New(conf, fm)
	const name = "snyk_code_enabled"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	conf.Set(cr.UserFolderKey(folderPath, name), &cr.LocalConfigField{Value: true, Changed: true})

	val, src := resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceUserFolderOverride, src)
	assert.Equal(t, true, val)
}

func Test_Resolver_WithClonedConfig(t *testing.T) {
	conf, fm := setupConf(t)
	clone := conf.Clone()

	resolver := cr.New(clone, fm)
	val, src := resolver.Resolve("snyk_code_enabled", "org123", "/workspace/project")
	assert.Equal(t, cr.ConfigSourceDefault, src)
	assert.Equal(t, false, val)
}

func Test_Resolve_AllSettingsCorrect(t *testing.T) {
	conf, fm := setupConf(t)
	resolver := cr.New(conf, fm)
	const orgID = "org123"
	const folderPath = "/workspace/project"

	machineFlags := fm.FlagsByAnnotation(cr.AnnotationScope, "machine")
	orgFlags := fm.FlagsByAnnotation(cr.AnnotationScope, "org")
	folderFlags := fm.FlagsByAnnotation(cr.AnnotationScope, "folder")

	assert.Contains(t, machineFlags, "api_endpoint")
	assert.Contains(t, orgFlags, "snyk_code_enabled")
	assert.Contains(t, folderFlags, "reference_branch")

	val, src := resolver.Resolve("api_endpoint", orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceDefault, src)
	assert.Equal(t, "", val)

	conf.Set(cr.UserGlobalKey("api_endpoint"), "https://user.example.com")
	val, src = resolver.Resolve("api_endpoint", orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceUserGlobal, src)
	assert.Equal(t, "https://user.example.com", val)

	conf.Set(cr.RemoteMachineKey("api_endpoint"), &cr.RemoteConfigField{Value: "https://remote.example.com"})
	val, src = resolver.Resolve("api_endpoint", orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceUserGlobal, src, "user global beats remote")
	assert.Equal(t, "https://user.example.com", val)

	val, src = resolver.Resolve("snyk_code_enabled", orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceDefault, src)
	assert.Equal(t, false, val)

	conf.Set(cr.RemoteOrgKey(orgID, "snyk_code_enabled"), &cr.RemoteConfigField{Value: true})
	val, src = resolver.Resolve("snyk_code_enabled", orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceRemote, src)
	assert.Equal(t, true, val)

	conf.Set(cr.UserFolderKey(folderPath, "snyk_code_enabled"), &cr.LocalConfigField{Value: false, Changed: true})
	val, src = resolver.Resolve("snyk_code_enabled", orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceUserFolderOverride, src)
	assert.Equal(t, false, val)

	val, src = resolver.Resolve("reference_branch", orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceDefault, src)
	assert.Equal(t, "", val)

	conf.Set(cr.UserFolderKey(folderPath, "reference_branch"), &cr.LocalConfigField{Value: "main", Changed: true})
	val, src = resolver.Resolve("reference_branch", orgID, folderPath)
	assert.Equal(t, cr.ConfigSourceFolder, src)
	assert.Equal(t, "main", val)

	name, found := fm.FlagNameByAnnotation(cr.AnnotationRemoteKey, "snyk_code_enabled")
	require.True(t, found)
	assert.Equal(t, "snyk_code_enabled", name)
	val, _ = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, false, val)
}

func Test_UserGlobalKey(t *testing.T) {
	assert.Equal(t, "user:global:snyk_code_enabled", cr.UserGlobalKey("snyk_code_enabled"))
}

func Test_UserFolderKey(t *testing.T) {
	assert.Equal(t, "user:folder:/path/to/folder:snyk_code_enabled", cr.UserFolderKey("/path/to/folder", "snyk_code_enabled"))
}

func Test_RemoteOrgKey(t *testing.T) {
	assert.Equal(t, "remote:org123:snyk_code_enabled", cr.RemoteOrgKey("org123", "snyk_code_enabled"))
}

func Test_RemoteMachineKey(t *testing.T) {
	assert.Equal(t, "remote:machine:api_endpoint", cr.RemoteMachineKey("api_endpoint"))
}

func Test_RemoteOrgFolderKey(t *testing.T) {
	assert.Equal(t, "remote:org123:folder:/path:snyk_code_enabled", cr.RemoteOrgFolderKey("org123", "/path", "snyk_code_enabled"))
}

func Test_FolderMetadataKey(t *testing.T) {
	assert.Equal(t, "folder:/path:preferred_org", cr.FolderMetadataKey("/path", "preferred_org"))
}
