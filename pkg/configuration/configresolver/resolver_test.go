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
	fm := workflow.NewConfigurationOptionsStore(workflow.ConfigurationOptionsFromFlagset(fs))
	return conf, fm
}

// --- Prefix key format tests ---

func Test_PrefixKeys(t *testing.T) {
	t.Run("UserGlobalKey", func(t *testing.T) {
		assert.Equal(t, "user:global:snyk_code_enabled", cr.UserGlobalKey("snyk_code_enabled"))
	})
	t.Run("UserFolderKey", func(t *testing.T) {
		assert.Equal(t, "user:folder:/path/to/folder:snyk_code_enabled", cr.UserFolderKey("/path/to/folder", "snyk_code_enabled"))
	})
	t.Run("RemoteOrgKey", func(t *testing.T) {
		assert.Equal(t, "remote:org123:snyk_code_enabled", cr.RemoteOrgKey("org123", "snyk_code_enabled"))
	})
	t.Run("RemoteMachineKey", func(t *testing.T) {
		assert.Equal(t, "remote:machine:api_endpoint", cr.RemoteMachineKey("api_endpoint"))
	})
	t.Run("RemoteOrgFolderKey", func(t *testing.T) {
		assert.Equal(t, "remote:org123:folder:/path:snyk_code_enabled", cr.RemoteOrgFolderKey("org123", "/path", "snyk_code_enabled"))
	})
	t.Run("FolderMetadataKey", func(t *testing.T) {
		assert.Equal(t, "folder:/path:preferred_org", cr.FolderMetadataKey("/path", "preferred_org"))
	})
	t.Run("colons in folder path do not collide with delimiter", func(t *testing.T) {
		key1 := cr.UserFolderKey("/normal/path", "name")
		key2 := cr.UserFolderKey("/path:with:colons", "name")
		assert.NotEqual(t, key1, key2)

		roundTripped := cr.UserFolderKey("C:\\Users\\foo", "snyk_code_enabled")
		conf := configuration.NewInMemory()
		conf.Set(roundTripped, &cr.LocalConfigField{Value: true, Changed: true})
		assert.NotNil(t, conf.Get(roundTripped))
	})
}

// --- Machine-scope resolution ---

func Test_Resolve_MachineScope(t *testing.T) {
	conf, fm := setupConf(t)
	resolver := cr.New(conf, fm)
	const name = "api_endpoint"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	t.Run("default when nothing set", func(t *testing.T) {
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceDefault, src)
		assert.Equal(t, "", val)
	})

	t.Run("remote machine value applied", func(t *testing.T) {
		conf.Set(cr.RemoteMachineKey(name), &cr.RemoteConfigField{Value: "https://remote.example.com"})
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceRemote, src)
		assert.Equal(t, "https://remote.example.com", val)
	})

	t.Run("user global overrides remote", func(t *testing.T) {
		conf.Set(cr.UserGlobalKey(name), "https://user.example.com")
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceUserGlobal, src)
		assert.Equal(t, "https://user.example.com", val)
	})

	t.Run("locked remote overrides user global", func(t *testing.T) {
		conf.Set(cr.RemoteMachineKey(name), &cr.RemoteConfigField{Value: "https://locked.example.com", IsLocked: true})
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceRemoteLocked, src)
		assert.Equal(t, "https://locked.example.com", val)
	})

	t.Run("org key is ignored for machine-scope setting", func(t *testing.T) {
		conf2, fm2 := setupConf(t)
		r2 := cr.New(conf2, fm2)
		conf2.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: "https://org.example.com"})
		val, src := r2.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceDefault, src)
		assert.Equal(t, "", val)
	})
}

// --- Org-scope resolution ---

func Test_Resolve_OrgScope(t *testing.T) {
	conf, fm := setupConf(t)
	resolver := cr.New(conf, fm)
	const name = "snyk_code_enabled"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	t.Run("default when nothing set", func(t *testing.T) {
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceDefault, src)
		assert.Equal(t, false, val)
	})

	t.Run("org-level remote applied", func(t *testing.T) {
		conf.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: true})
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceRemote, src)
		assert.Equal(t, true, val)
	})

	t.Run("folder-level remote overrides org-level remote", func(t *testing.T) {
		conf.Set(cr.RemoteOrgFolderKey(orgID, folderPath, name), &cr.RemoteConfigField{Value: false})
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceRemote, src)
		assert.Equal(t, false, val)
	})

	t.Run("user global overrides non-locked remote", func(t *testing.T) {
		conf.Set(cr.UserGlobalKey(name), true)
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceUserGlobal, src)
		assert.Equal(t, true, val)
	})

	t.Run("user folder override overrides user global", func(t *testing.T) {
		conf.Set(cr.UserFolderKey(folderPath, name), &cr.LocalConfigField{Value: false, Changed: true})
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceUserFolderOverride, src)
		assert.Equal(t, false, val)
	})

	t.Run("org-level locked remote overrides user override", func(t *testing.T) {
		conf.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: true, IsLocked: true})
		conf.Set(cr.RemoteOrgFolderKey(orgID, folderPath, name), &cr.RemoteConfigField{Value: false})
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceRemoteLocked, src)
		assert.Equal(t, true, val)
	})

	t.Run("folder-level locked remote overrides org-level locked remote", func(t *testing.T) {
		conf.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: true, IsLocked: true})
		conf.Set(cr.RemoteOrgFolderKey(orgID, folderPath, name), &cr.RemoteConfigField{Value: false, IsLocked: true})
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceRemoteLocked, src)
		assert.Equal(t, false, val)
	})

	t.Run("unchanged LocalConfigField is not treated as override", func(t *testing.T) {
		conf2, fm2 := setupConf(t)
		r2 := cr.New(conf2, fm2)
		conf2.Set(cr.UserFolderKey(folderPath, name), &cr.LocalConfigField{Value: true, Changed: false})
		_, src := r2.Resolve(name, orgID, folderPath)
		assert.NotEqual(t, cr.ConfigSourceUserFolderOverride, src)
	})

	t.Run("locked folder remote overrides all other sources at once", func(t *testing.T) {
		conf2, fm2 := setupConf(t)
		r2 := cr.New(conf2, fm2)
		conf2.Set(cr.UserGlobalKey(name), true)
		conf2.Set(cr.UserFolderKey(folderPath, name), &cr.LocalConfigField{Value: true, Changed: true})
		conf2.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: true})
		conf2.Set(cr.RemoteOrgFolderKey(orgID, folderPath, name), &cr.RemoteConfigField{Value: false, IsLocked: true})

		val, src := r2.Resolve(name, orgID, folderPath)
		assert.Equal(t, false, val)
		assert.Equal(t, cr.ConfigSourceRemoteLocked, src)
	})

	t.Run("different orgs return different remote values", func(t *testing.T) {
		conf2, fm2 := setupConf(t)
		r2 := cr.New(conf2, fm2)
		conf2.Set(cr.RemoteOrgKey("org-A", name), &cr.RemoteConfigField{Value: true})
		conf2.Set(cr.RemoteOrgKey("org-B", name), &cr.RemoteConfigField{Value: false})

		valA, _ := r2.Resolve(name, "org-A", folderPath)
		valB, _ := r2.Resolve(name, "org-B", folderPath)
		assert.Equal(t, true, valA)
		assert.Equal(t, false, valB)
	})

	t.Run("multi-folder with different folder-level remotes", func(t *testing.T) {
		conf2, fm2 := setupConf(t)
		r2 := cr.New(conf2, fm2)
		const folder1 = "/workspace/folder1"
		const folder2 = "/workspace/folder2"

		conf2.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: true})
		conf2.Set(cr.RemoteOrgFolderKey(orgID, folder1, name), &cr.RemoteConfigField{Value: false})

		val1, _ := r2.Resolve(name, orgID, folder1)
		val2, _ := r2.Resolve(name, orgID, folder2)
		assert.Equal(t, false, val1, "folder1 should use folder-level remote")
		assert.Equal(t, true, val2, "folder2 should fall back to org-level remote")
	})

	t.Run("empty folderPath ignores folder-level remote", func(t *testing.T) {
		conf2, fm2 := setupConf(t)
		r2 := cr.New(conf2, fm2)
		conf2.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: true})
		conf2.Set(cr.RemoteOrgFolderKey(orgID, "/workspace/x", name), &cr.RemoteConfigField{Value: false})

		val, src := r2.Resolve(name, orgID, "")
		assert.Equal(t, true, val)
		assert.Equal(t, cr.ConfigSourceRemote, src)
	})
}

// --- Folder-scope resolution ---

func Test_Resolve_FolderScope(t *testing.T) {
	const name = "reference_branch"
	const orgID = "org123"
	const folderPath = "/workspace/project"

	t.Run("default when nothing set", func(t *testing.T) {
		conf, fm := setupConf(t)
		resolver := cr.New(conf, fm)
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceDefault, src)
		assert.Equal(t, "", val)
	})

	t.Run("folder value applied", func(t *testing.T) {
		conf, fm := setupConf(t)
		resolver := cr.New(conf, fm)
		conf.Set(cr.UserFolderKey(folderPath, name), &cr.LocalConfigField{Value: "main", Changed: true})
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceFolder, src)
		assert.Equal(t, "main", val)
	})

	t.Run("remote org value applied when no folder value", func(t *testing.T) {
		conf, fm := setupConf(t)
		resolver := cr.New(conf, fm)
		conf.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: "develop"})
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceRemote, src)
		assert.Equal(t, "develop", val)
	})

	t.Run("remote folder value takes precedence over remote org value", func(t *testing.T) {
		conf, fm := setupConf(t)
		resolver := cr.New(conf, fm)
		conf.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: "develop"})
		conf.Set(cr.RemoteOrgFolderKey(orgID, folderPath, name), &cr.RemoteConfigField{Value: "release"})
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceRemote, src)
		assert.Equal(t, "release", val)
	})

	t.Run("folder value overrides non-locked remote", func(t *testing.T) {
		conf, fm := setupConf(t)
		resolver := cr.New(conf, fm)
		conf.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: "develop"})
		conf.Set(cr.UserFolderKey(folderPath, name), &cr.LocalConfigField{Value: "main", Changed: true})
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceFolder, src)
		assert.Equal(t, "main", val)
	})

	t.Run("locked remote org overrides folder value", func(t *testing.T) {
		conf, fm := setupConf(t)
		resolver := cr.New(conf, fm)
		conf.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: "develop", IsLocked: true})
		conf.Set(cr.UserFolderKey(folderPath, name), &cr.LocalConfigField{Value: "main", Changed: true})
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceRemoteLocked, src)
		assert.Equal(t, "develop", val)
	})

	t.Run("locked remote folder overrides locked remote org", func(t *testing.T) {
		conf, fm := setupConf(t)
		resolver := cr.New(conf, fm)
		conf.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: "develop", IsLocked: true})
		conf.Set(cr.RemoteOrgFolderKey(orgID, folderPath, name), &cr.RemoteConfigField{Value: "release", IsLocked: true})
		val, src := resolver.Resolve(name, orgID, folderPath)
		assert.Equal(t, cr.ConfigSourceRemoteLocked, src)
		assert.Equal(t, "release", val)
	})
}

// --- IsLocked ---

func Test_IsLocked(t *testing.T) {
	conf, fm := setupConf(t)
	resolver := cr.New(conf, fm)
	const name = "snyk_code_enabled"
	const orgID = "org-lock"
	const folderPath = "/workspace/lock"

	t.Run("false when nothing set", func(t *testing.T) {
		assert.False(t, resolver.IsLocked(name, orgID, folderPath))
	})

	t.Run("false when org remote is not locked", func(t *testing.T) {
		conf.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: true, IsLocked: false})
		assert.False(t, resolver.IsLocked(name, orgID, folderPath))
	})

	t.Run("true when org remote is locked", func(t *testing.T) {
		conf.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: true, IsLocked: true})
		assert.True(t, resolver.IsLocked(name, orgID, folderPath))
	})

	t.Run("true when folder remote is locked even if org remote is not", func(t *testing.T) {
		conf.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: true, IsLocked: false})
		conf.Set(cr.RemoteOrgFolderKey(orgID, folderPath, name), &cr.RemoteConfigField{Value: false, IsLocked: true})
		assert.True(t, resolver.IsLocked(name, orgID, folderPath))
	})

	t.Run("false when both folder and org remote are not locked", func(t *testing.T) {
		conf.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: true, IsLocked: false})
		conf.Set(cr.RemoteOrgFolderKey(orgID, folderPath, name), &cr.RemoteConfigField{Value: false, IsLocked: false})
		assert.False(t, resolver.IsLocked(name, orgID, folderPath))
	})

	t.Run("without folderPath only checks org level", func(t *testing.T) {
		conf.Set(cr.RemoteOrgKey(orgID, name), &cr.RemoteConfigField{Value: true, IsLocked: false})
		conf.Set(cr.RemoteOrgFolderKey(orgID, folderPath, name), &cr.RemoteConfigField{Value: false, IsLocked: true})
		assert.False(t, resolver.IsLocked(name, orgID))
	})

	t.Run("machine-scope ignores folder-level lock", func(t *testing.T) {
		conf.Set(cr.RemoteOrgFolderKey(orgID, folderPath, "api_endpoint"), &cr.RemoteConfigField{Value: "x", IsLocked: true})
		conf.Set(cr.RemoteMachineKey("api_endpoint"), &cr.RemoteConfigField{Value: "y", IsLocked: false})
		assert.False(t, resolver.IsLocked("api_endpoint", orgID, folderPath))
	})

	t.Run("machine-scope locked via RemoteMachineKey", func(t *testing.T) {
		conf2, fm2 := setupConf(t)
		r2 := cr.New(conf2, fm2)
		conf2.Set(cr.RemoteMachineKey("api_endpoint"), &cr.RemoteConfigField{Value: "https://locked.example.com", IsLocked: true})
		assert.True(t, r2.IsLocked("api_endpoint", "any-org"))
	})
}

// --- ResolveBool ---

func Test_ResolveBool(t *testing.T) {
	t.Run("returns false for default bool", func(t *testing.T) {
		conf, fm := setupConf(t)
		resolver := cr.New(conf, fm)
		assert.False(t, resolver.ResolveBool("snyk_code_enabled", "org123", "/workspace/project"))
	})

	t.Run("returns true for native bool true", func(t *testing.T) {
		conf, fm := setupConf(t)
		resolver := cr.New(conf, fm)
		conf.Set(cr.UserGlobalKey("snyk_code_enabled"), true)
		assert.True(t, resolver.ResolveBool("snyk_code_enabled", "org123", "/workspace/project"))
	})

	t.Run("parses string true", func(t *testing.T) {
		conf, fm := setupConf(t)
		resolver := cr.New(conf, fm)
		conf.Set(cr.UserGlobalKey("snyk_code_enabled"), "true")
		assert.True(t, resolver.ResolveBool("snyk_code_enabled", "org123", "/workspace/project"))
	})

	t.Run("parses string false", func(t *testing.T) {
		conf, fm := setupConf(t)
		resolver := cr.New(conf, fm)
		conf.Set(cr.UserGlobalKey("snyk_code_enabled"), "false")
		assert.False(t, resolver.ResolveBool("snyk_code_enabled", "org123", "/workspace/project"))
	})

	t.Run("parses string 1 as true", func(t *testing.T) {
		conf, fm := setupConf(t)
		resolver := cr.New(conf, fm)
		conf.Set(cr.UserGlobalKey("snyk_code_enabled"), "1")
		assert.True(t, resolver.ResolveBool("snyk_code_enabled", "org123", "/workspace/project"))
	})

	t.Run("treats int 1 as true", func(t *testing.T) {
		conf, fm := setupConf(t)
		resolver := cr.New(conf, fm)
		conf.Set(cr.UserGlobalKey("snyk_code_enabled"), 1)
		assert.True(t, resolver.ResolveBool("snyk_code_enabled", "org123", "/workspace/project"))
	})

	t.Run("treats int 0 as false", func(t *testing.T) {
		conf, fm := setupConf(t)
		resolver := cr.New(conf, fm)
		conf.Set(cr.UserGlobalKey("snyk_code_enabled"), 0)
		assert.False(t, resolver.ResolveBool("snyk_code_enabled", "org123", "/workspace/project"))
	})

	t.Run("treats float64 1 as true (JSON unmarshal)", func(t *testing.T) {
		conf, fm := setupConf(t)
		resolver := cr.New(conf, fm)
		conf.Set(cr.UserGlobalKey("snyk_code_enabled"), float64(1))
		assert.True(t, resolver.ResolveBool("snyk_code_enabled", "org123", "/workspace/project"))
	})

	t.Run("treats float64 0 as false", func(t *testing.T) {
		conf, fm := setupConf(t)
		resolver := cr.New(conf, fm)
		conf.Set(cr.UserGlobalKey("snyk_code_enabled"), float64(0))
		assert.False(t, resolver.ResolveBool("snyk_code_enabled", "org123", "/workspace/project"))
	})
}

// --- Cross-scope ---

func Test_Resolve_CrossScope(t *testing.T) {
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

func Test_Resolve_WorksWithClonedConfig(t *testing.T) {
	conf, fm := setupConf(t)
	clone := conf.Clone()

	resolver := cr.New(clone, fm)
	val, src := resolver.Resolve("snyk_code_enabled", "org123", "/workspace/project")
	assert.Equal(t, cr.ConfigSourceDefault, src)
	assert.Equal(t, false, val)
}
