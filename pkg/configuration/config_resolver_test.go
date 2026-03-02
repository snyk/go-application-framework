package configuration

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// representativeFlagSet creates a flagset with machine, org, and folder scoped flags for FC-100.
func representativeFlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("fc100", pflag.ContinueOnError)
	// Machine-scope
	fs.String("api_endpoint", "", "API endpoint URL")
	fs.Lookup("api_endpoint").Annotations = map[string][]string{
		AnnotationScope:       {"machine"},
		AnnotationRemoteKey:   {"api_endpoint"},
		AnnotationDisplayName: {"API Endpoint"},
		AnnotationIdeKey:      {"endpoint"},
	}
	// Org-scope
	fs.Bool("snyk_code_enabled", false, "Enable Snyk Code analysis")
	fs.Lookup("snyk_code_enabled").Annotations = map[string][]string{
		AnnotationScope:       {"org"},
		AnnotationRemoteKey:   {"snyk_code_enabled"},
		AnnotationDisplayName: {"Snyk Code"},
		AnnotationIdeKey:      {"activateSnykCode"},
	}
	// Folder-scope
	fs.String("reference_branch", "", "Reference branch for delta findings")
	fs.Lookup("reference_branch").Annotations = map[string][]string{
		AnnotationScope:       {"folder"},
		AnnotationDisplayName: {"Reference Branch"},
	}
	return fs
}

// FC-100: ConfigResolver resolves all registered settings correctly using flag annotations and prefix keys.
func Test_FC100_Resolver_AllSettingsCorrect(t *testing.T) {
	conf := NewInMemory()
	fm, ok := conf.(FlagMetadata)
	require.True(t, ok, "Configuration must implement FlagMetadata")

	fs := representativeFlagSet()
	err := conf.AddFlagSet(fs)
	require.NoError(t, err)

	resolver := NewConfigResolver(conf)
	const orgID = "org123"
	const folderPath = "/workspace/project"

	// 1. FlagsByAnnotation returns correct flags per scope
	machineFlags := fm.FlagsByAnnotation(AnnotationScope, "machine")
	orgFlags := fm.FlagsByAnnotation(AnnotationScope, "org")
	folderFlags := fm.FlagsByAnnotation(AnnotationScope, "folder")

	assert.Contains(t, machineFlags, "api_endpoint")
	assert.Contains(t, orgFlags, "snyk_code_enabled")
	assert.Contains(t, folderFlags, "reference_branch")

	// 2. Machine-scope: Resolve uses default, then user global, then remote
	val, src := resolver.Resolve("api_endpoint", orgID, folderPath)
	assert.Equal(t, ConfigSourceDefault, src)
	assert.Equal(t, "", val)

	conf.Set(UserGlobalKey("api_endpoint"), "https://user.example.com")
	val, src = resolver.Resolve("api_endpoint", orgID, folderPath)
	assert.Equal(t, ConfigSourceUserGlobal, src)
	assert.Equal(t, "https://user.example.com", val)

	conf.Set(RemoteOrgKey(orgID, "api_endpoint"), &RemoteConfigField{Value: "https://remote.example.com"})
	val, src = resolver.Resolve("api_endpoint", orgID, folderPath)
	assert.Equal(t, ConfigSourceUserGlobal, src, "user global beats remote")
	assert.Equal(t, "https://user.example.com", val)

	// 3. Org-scope: Resolve uses default, then remote, then folder override
	val, src = resolver.Resolve("snyk_code_enabled", orgID, folderPath)
	assert.Equal(t, ConfigSourceDefault, src)
	assert.Equal(t, false, val)

	conf.Set(RemoteOrgKey(orgID, "snyk_code_enabled"), &RemoteConfigField{Value: true})
	val, src = resolver.Resolve("snyk_code_enabled", orgID, folderPath)
	assert.Equal(t, ConfigSourceRemote, src)
	assert.Equal(t, true, val)

	conf.Set(UserFolderKey(folderPath, "snyk_code_enabled"), &LocalConfigField{Value: false, Changed: true})
	val, src = resolver.Resolve("snyk_code_enabled", orgID, folderPath)
	assert.Equal(t, ConfigSourceUserOverride, src)
	assert.Equal(t, false, val)

	// 4. Folder-scope: Resolve uses default, then folder value
	val, src = resolver.Resolve("reference_branch", orgID, folderPath)
	assert.Equal(t, ConfigSourceDefault, src)
	assert.Equal(t, "", val)

	conf.Set(UserFolderKey(folderPath, "reference_branch"), &LocalConfigField{Value: "main", Changed: true})
	val, src = resolver.Resolve("reference_branch", orgID, folderPath)
	assert.Equal(t, ConfigSourceFolder, src)
	assert.Equal(t, "main", val)

	// 5. FlagNameByAnnotation + Resolve: remote key maps to flag name
	name, found := fm.FlagNameByAnnotation(AnnotationRemoteKey, "snyk_code_enabled")
	require.True(t, found)
	assert.Equal(t, "snyk_code_enabled", name)
	val, _ = resolver.Resolve(name, orgID, folderPath)
	assert.Equal(t, false, val)
}
