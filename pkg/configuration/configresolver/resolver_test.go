package configresolver_test

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
)

func newFlagSetWithAnnotations() *pflag.FlagSet {
	fs := pflag.NewFlagSet("test-flags", pflag.ContinueOnError)
	fs.String("api_endpoint", "", "API endpoint URL")
	fs.Lookup("api_endpoint").Annotations = map[string][]string{
		configuration.AnnotationScope:       {"machine"},
		configuration.AnnotationRemoteKey:   {"api_endpoint"},
		configuration.AnnotationDisplayName: {"API Endpoint"},
		configuration.AnnotationIdeKey:      {"endpoint"},
	}
	fs.Bool("snyk_code_enabled", false, "Enable Snyk Code analysis")
	fs.Lookup("snyk_code_enabled").Annotations = map[string][]string{
		configuration.AnnotationScope:       {"org"},
		configuration.AnnotationRemoteKey:   {"snyk_code_enabled"},
		configuration.AnnotationDisplayName: {"Snyk Code"},
		configuration.AnnotationIdeKey:      {"activateSnykCode"},
	}
	fs.String("reference_branch", "", "Reference branch for delta findings")
	fs.Lookup("reference_branch").Annotations = map[string][]string{
		configuration.AnnotationScope:       {"folder"},
		configuration.AnnotationDisplayName: {"Reference Branch"},
	}
	return fs
}

func setupConf(t *testing.T) configuration.Configuration {
	t.Helper()
	conf := configuration.NewInMemory()
	require.NoError(t, conf.AddFlagSet(newFlagSetWithAnnotations()))
	return conf
}

func Test_Resolve_MachineScope_Precedence(t *testing.T) {
	conf := setupConf(t)
	resolver := configresolver.New(conf)
	const name = "api_endpoint"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	val, src := resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceDefault, src)
	assert.Equal(t, "", val)

	conf.Set(configuration.RemoteMachineKey(name), &configuration.RemoteConfigField{Value: "https://remote.example.com"})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceRemote, src)
	assert.Equal(t, "https://remote.example.com", val)

	conf.Set(configuration.UserGlobalKey(name), "https://user.example.com")
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceUserGlobal, src)
	assert.Equal(t, "https://user.example.com", val)

	conf.Set(configuration.RemoteMachineKey(name), &configuration.RemoteConfigField{Value: "https://locked.example.com", IsLocked: true})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceRemoteLocked, src)
	assert.Equal(t, "https://locked.example.com", val)
}

func Test_Resolve_OrgScope_Precedence(t *testing.T) {
	conf := setupConf(t)
	resolver := configresolver.New(conf)
	const name = "snyk_code_enabled"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	val, src := resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceDefault, src)
	assert.Equal(t, false, val)

	conf.Set(configuration.RemoteOrgKey(orgID, name), &configuration.RemoteConfigField{Value: true})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceRemote, src)
	assert.Equal(t, true, val)

	conf.Set(configuration.UserGlobalKey(name), true)
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceUserGlobal, src)
	assert.Equal(t, true, val)

	conf.Set(configuration.UserFolderKey(folderPath, name), &configuration.LocalConfigField{Value: false, Changed: true})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceUserFolderOverride, src)
	assert.Equal(t, false, val)

	conf.Set(configuration.RemoteOrgKey(orgID, name), &configuration.RemoteConfigField{Value: false, IsLocked: true})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceRemoteLocked, src)
	assert.Equal(t, false, val)
}

func Test_Resolve_FolderScope(t *testing.T) {
	conf := setupConf(t)
	resolver := configresolver.New(conf)
	const name = "reference_branch"
	const folderPath = "/workspace/project"

	val, src := resolver.Resolve(name, "", folderPath)
	assert.Equal(t, configuration.ConfigSourceDefault, src)
	assert.Equal(t, "", val)

	conf.Set(configuration.UserFolderKey(folderPath, name), &configuration.LocalConfigField{Value: "main", Changed: true})
	val, src = resolver.Resolve(name, "", folderPath)
	assert.Equal(t, configuration.ConfigSourceFolder, src)
	assert.Equal(t, "main", val)
}

func Test_Resolve_Stateless_OrgParameter(t *testing.T) {
	conf := setupConf(t)
	resolver := configresolver.New(conf)
	const name = "snyk_code_enabled"
	const folderPath = "/workspace/project"

	conf.Set(configuration.RemoteOrgKey("org-A", name), &configuration.RemoteConfigField{Value: true})
	conf.Set(configuration.RemoteOrgKey("org-B", name), &configuration.RemoteConfigField{Value: false})

	valA, _ := resolver.Resolve(name, "org-A", folderPath)
	valB, _ := resolver.Resolve(name, "org-B", folderPath)

	assert.Equal(t, true, valA)
	assert.Equal(t, false, valB)
}

func Test_IsLocked_ReadsRemote(t *testing.T) {
	conf := setupConf(t)
	resolver := configresolver.New(conf)
	const name = "snyk_code_enabled"
	const orgID = "org123"

	assert.False(t, resolver.IsLocked(name, orgID))

	conf.Set(configuration.RemoteOrgKey(orgID, name), &configuration.RemoteConfigField{Value: true, IsLocked: true})
	assert.True(t, resolver.IsLocked(name, orgID))
}

func Test_LocalConfigField_ChangedRequired(t *testing.T) {
	conf := setupConf(t)
	resolver := configresolver.New(conf)
	const name = "snyk_code_enabled"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	conf.Set(configuration.UserFolderKey(folderPath, name), &configuration.LocalConfigField{Value: true, Changed: false})
	_, src := resolver.Resolve(name, orgID, folderPath)
	assert.NotEqual(t, configuration.ConfigSourceUserFolderOverride, src, "Changed:false override must not apply")
}

func Test_ResolveBool(t *testing.T) {
	conf := setupConf(t)
	resolver := configresolver.New(conf)
	const orgID = "org123"
	const folderPath = "/workspace/project"

	assert.False(t, resolver.ResolveBool("snyk_code_enabled", orgID, folderPath))

	conf.Set(configuration.UserGlobalKey("snyk_code_enabled"), true)
	assert.True(t, resolver.ResolveBool("snyk_code_enabled", orgID, folderPath))
}

func Test_ResolveMachine_UsesMachineKey(t *testing.T) {
	conf := setupConf(t)
	resolver := configresolver.New(conf)
	const name = "api_endpoint"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	conf.Set(configuration.RemoteMachineKey(name), &configuration.RemoteConfigField{Value: "https://machine.example.com"})
	val, src := resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceRemote, src)
	assert.Equal(t, "https://machine.example.com", val)

	conf.Unset(configuration.RemoteMachineKey(name))
	conf.Set(configuration.RemoteOrgKey(orgID, name), &configuration.RemoteConfigField{Value: "https://org.example.com"})
	val, src = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceDefault, src, "org key must not apply to machine-scope setting")
	assert.Equal(t, "", val)
}

func Test_IsLocked_MachineScope(t *testing.T) {
	conf := setupConf(t)
	resolver := configresolver.New(conf)
	const name = "api_endpoint"

	conf.Set(configuration.RemoteMachineKey(name), &configuration.RemoteConfigField{Value: "https://locked.example.com", IsLocked: true})
	assert.True(t, resolver.IsLocked(name, "any-org"))
}

func Test_FolderOverride_FromPrefixKeys(t *testing.T) {
	conf := setupConf(t)
	resolver := configresolver.New(conf)
	const name = "snyk_code_enabled"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	conf.Set(configuration.UserFolderKey(folderPath, name), &configuration.LocalConfigField{Value: true, Changed: true})

	val, src := resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceUserFolderOverride, src)
	assert.Equal(t, true, val)
}

func Test_Resolver_WithClonedConfig(t *testing.T) {
	conf := setupConf(t)
	clone := conf.Clone()

	resolver := configresolver.New(clone)
	val, src := resolver.Resolve("snyk_code_enabled", "org123", "/workspace/project")
	assert.Equal(t, configuration.ConfigSourceDefault, src)
	assert.Equal(t, false, val)
}

func Test_Resolve_AllSettingsCorrect(t *testing.T) {
	conf := configuration.NewInMemory()
	fm, ok := conf.(configuration.FlagMetadata)
	require.True(t, ok)

	fs := newFlagSetWithAnnotations()
	require.NoError(t, conf.AddFlagSet(fs))

	resolver := configresolver.New(conf)
	const orgID = "org123"
	const folderPath = "/workspace/project"

	machineFlags := fm.FlagsByAnnotation(configuration.AnnotationScope, "machine")
	orgFlags := fm.FlagsByAnnotation(configuration.AnnotationScope, "org")
	folderFlags := fm.FlagsByAnnotation(configuration.AnnotationScope, "folder")

	assert.Contains(t, machineFlags, "api_endpoint")
	assert.Contains(t, orgFlags, "snyk_code_enabled")
	assert.Contains(t, folderFlags, "reference_branch")

	val, src := resolver.Resolve("api_endpoint", orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceDefault, src)
	assert.Equal(t, "", val)

	conf.Set(configuration.UserGlobalKey("api_endpoint"), "https://user.example.com")
	val, src = resolver.Resolve("api_endpoint", orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceUserGlobal, src)
	assert.Equal(t, "https://user.example.com", val)

	conf.Set(configuration.RemoteMachineKey("api_endpoint"), &configuration.RemoteConfigField{Value: "https://remote.example.com"})
	val, src = resolver.Resolve("api_endpoint", orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceUserGlobal, src, "user global beats remote")
	assert.Equal(t, "https://user.example.com", val)

	val, src = resolver.Resolve("snyk_code_enabled", orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceDefault, src)
	assert.Equal(t, false, val)

	conf.Set(configuration.RemoteOrgKey(orgID, "snyk_code_enabled"), &configuration.RemoteConfigField{Value: true})
	val, src = resolver.Resolve("snyk_code_enabled", orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceRemote, src)
	assert.Equal(t, true, val)

	conf.Set(configuration.UserFolderKey(folderPath, "snyk_code_enabled"), &configuration.LocalConfigField{Value: false, Changed: true})
	val, src = resolver.Resolve("snyk_code_enabled", orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceUserFolderOverride, src)
	assert.Equal(t, false, val)

	val, src = resolver.Resolve("reference_branch", orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceDefault, src)
	assert.Equal(t, "", val)

	conf.Set(configuration.UserFolderKey(folderPath, "reference_branch"), &configuration.LocalConfigField{Value: "main", Changed: true})
	val, src = resolver.Resolve("reference_branch", orgID, folderPath)
	assert.Equal(t, configuration.ConfigSourceFolder, src)
	assert.Equal(t, "main", val)

	name, found := fm.FlagNameByAnnotation(configuration.AnnotationRemoteKey, "snyk_code_enabled")
	require.True(t, found)
	assert.Equal(t, "snyk_code_enabled", name)
	val, _ = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, false, val)
}
