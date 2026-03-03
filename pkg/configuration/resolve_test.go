package configuration

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newResolveTestConf creates a config with an annotated flagset for Resolve tests.
// The flagset registers three flags: one org-scoped, one folder-scoped, one machine-scoped.
func newResolveTestConf(t *testing.T) Configuration {
	t.Helper()
	conf := NewInMemory()

	fs := pflag.NewFlagSet("resolve-test", pflag.ContinueOnError)
	fs.Bool("org_flag", false, "org-scoped flag")
	fs.Lookup("org_flag").Annotations = map[string][]string{
		AnnotationScope: {"org"},
	}
	fs.Bool("folder_flag", false, "folder-scoped flag")
	fs.Lookup("folder_flag").Annotations = map[string][]string{
		AnnotationScope: {"folder"},
	}
	fs.Bool("machine_flag", false, "machine-scoped flag")
	fs.Lookup("machine_flag").Annotations = map[string][]string{
		AnnotationScope: {"machine"},
	}
	fs.Bool("unscoped_flag", false, "no scope annotation")

	require.NoError(t, conf.AddFlagSet(fs))
	return conf
}

// Test_Resolve_OrgScope_MissingOrg_ReturnsError verifies that Resolve returns
// ErrMissingOrganization for an org-scoped setting when ORGANIZATION is not set.
func Test_Resolve_OrgScope_MissingOrg_ReturnsError(t *testing.T) {
	conf := newResolveTestConf(t)
	conf.Set(INPUT_DIRECTORY, []string{"/some/dir"})
	// ORGANIZATION intentionally not set

	_, _, err := conf.Resolve("org_flag")
	require.Error(t, err)

	assert.ErrorIs(t, err, ErrMissingOrganization)
}

// Test_Resolve_OrgScope_MissingInputDir_ReturnsError verifies that Resolve returns
// ErrMissingInputDirectory for an org-scoped setting when INPUT_DIRECTORY is empty.
func Test_Resolve_OrgScope_MissingInputDir_ReturnsError(t *testing.T) {
	conf := newResolveTestConf(t)
	conf.Set(ORGANIZATION, "org-123")
	// INPUT_DIRECTORY intentionally not set

	_, _, err := conf.Resolve("org_flag")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingInputDirectory)
}

// Test_Resolve_FolderScope_MissingInputDir_ReturnsError verifies that Resolve returns
// ErrMissingInputDirectory for a folder-scoped setting when INPUT_DIRECTORY is empty.
func Test_Resolve_FolderScope_MissingInputDir_ReturnsError(t *testing.T) {
	conf := newResolveTestConf(t)
	// Neither INPUT_DIRECTORY nor ORGANIZATION set

	_, _, err := conf.Resolve("folder_flag")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingInputDirectory)
}

// Test_Resolve_MachineScope_NoOrgNoDir_OK verifies that machine-scoped settings
// resolve without requiring ORGANIZATION or INPUT_DIRECTORY.
func Test_Resolve_MachineScope_NoOrgNoDir_OK(t *testing.T) {
	conf := newResolveTestConf(t)
	conf.Set(RemoteMachineKey("machine_flag"), &RemoteConfigField{Value: true})

	val, src, err := conf.Resolve("machine_flag")
	require.NoError(t, err)
	assert.Equal(t, ConfigSourceRemote, src)
	assert.Equal(t, true, val)
}

// Test_Resolve_UnscopedFlag_NoOrgNoDir_OK verifies that unscoped settings
// resolve without requiring ORGANIZATION or INPUT_DIRECTORY.
func Test_Resolve_UnscopedFlag_NoOrgNoDir_OK(t *testing.T) {
	conf := newResolveTestConf(t)
	conf.Set("unscoped_flag", true)

	val, src, err := conf.Resolve("unscoped_flag")
	require.NoError(t, err)
	assert.Equal(t, ConfigSourceDefault, src)
	assert.Equal(t, true, val)
}

// Test_Resolve_InputDirectorySlice_UsesFirstElement verifies that when INPUT_DIRECTORY
// contains exactly one entry it is used as the folder path for resolution.
func Test_Resolve_InputDirectorySlice_UsesFirstElement(t *testing.T) {
	conf := newResolveTestConf(t)
	conf.Set(ORGANIZATION, "org-123")
	conf.Set(INPUT_DIRECTORY, []string{"/project/root"})
	conf.Set(UserFolderKey("/project/root", "org_flag"), &LocalConfigField{Value: true, Changed: true})

	val, src, err := conf.Resolve("org_flag")
	require.NoError(t, err)
	assert.Equal(t, ConfigSourceUserOverride, src)
	assert.Equal(t, true, val)
}

// Test_Resolve_MultipleInputDirectories_FallsBackToGet verifies that when INPUT_DIRECTORY
// contains more than one entry, Resolve falls back to plain conf.Get (non-resolved retrieval).
func Test_Resolve_MultipleInputDirectories_FallsBackToGet(t *testing.T) {
	conf := newResolveTestConf(t)
	conf.Set(ORGANIZATION, "org-123")
	conf.Set(INPUT_DIRECTORY, []string{"/project/a", "/project/b"})
	// Set a user-folder override that should NOT be picked up in fallback mode
	conf.Set(UserFolderKey("/project/a", "org_flag"), &LocalConfigField{Value: true, Changed: true})
	// Set the bare key to a known value
	conf.Set("org_flag", false)

	val, src, err := conf.Resolve("org_flag")
	require.NoError(t, err)
	assert.Equal(t, ConfigSourceDefault, src)
	assert.Equal(t, false, val)
}

// Test_Resolve_OrgScope_ReturnsResolvedValue verifies the happy path for an org-scoped setting.
func Test_Resolve_OrgScope_ReturnsResolvedValue(t *testing.T) {
	conf := newResolveTestConf(t)
	conf.Set(ORGANIZATION, "org-abc")
	conf.Set(INPUT_DIRECTORY, []string{"/workspace"})
	conf.Set(RemoteOrgKey("org-abc", "org_flag"), &RemoteConfigField{Value: true})

	val, src, err := conf.Resolve("org_flag")
	require.NoError(t, err)
	assert.Equal(t, ConfigSourceRemote, src)
	assert.Equal(t, true, val)
}

// Test_Resolve_InputDirectoryAsString verifies that a plain string INPUT_DIRECTORY
// (not a slice) is handled correctly.
func Test_Resolve_InputDirectoryAsString(t *testing.T) {
	conf := newResolveTestConf(t)
	conf.Set(ORGANIZATION, "org-123")
	conf.Set(INPUT_DIRECTORY, "/single/dir")
	conf.Set(UserGlobalKey("org_flag"), true)

	val, src, err := conf.Resolve("org_flag")
	require.NoError(t, err)
	assert.Equal(t, ConfigSourceUserGlobal, src)
	assert.Equal(t, true, val)
}

// Test_ResolveDefaultFunc_UsesResolvedValue verifies that a DefaultValueFunction
// built with ResolveDefaultFunc returns the resolved value when the resolver
// finds a prefixed key (non-default source).
func Test_ResolveDefaultFunc_UsesResolvedValue(t *testing.T) {
	conf := newResolveTestConf(t)
	conf.Set(ORGANIZATION, "org-123")
	conf.Set(INPUT_DIRECTORY, []string{"/workspace"})
	conf.Set(RemoteOrgKey("org-123", "org_flag"), &RemoteConfigField{Value: true})

	conf.AddDefaultValue("org_flag", ResolveDefaultFunc("org_flag"))

	val := conf.GetBool("org_flag")
	assert.True(t, val)
}

// Test_ResolveDefaultFunc_NilWhenDefaultSource verifies that ResolveDefaultFunc
// does NOT cause infinite recursion: when the resolver falls through to ConfigSourceDefault,
// the function returns existingValue rather than recursing.
func Test_ResolveDefaultFunc_NilWhenDefaultSource(t *testing.T) {
	conf := newResolveTestConf(t)
	conf.Set(ORGANIZATION, "org-123")
	conf.Set(INPUT_DIRECTORY, []string{"/workspace"})
	// Nothing set — resolver will fall through to ConfigSourceDefault

	conf.AddDefaultValue("org_flag", ResolveDefaultFunc("org_flag"))

	// Must not hang or panic. Returns the flag's registered default (false).
	val := conf.GetBool("org_flag")
	assert.False(t, val)
}

// Test_ResolveDefaultFunc_ErrorPropagated verifies that errors from Resolve
// (e.g. missing org) are surfaced through GetWithError.
func Test_ResolveDefaultFunc_ErrorPropagated(t *testing.T) {
	conf := newResolveTestConf(t)
	conf.Set(INPUT_DIRECTORY, []string{"/workspace"})
	// ORGANIZATION not set → Resolve will return ErrMissingOrganization

	conf.AddDefaultValue("org_flag", ResolveDefaultFunc("org_flag"))

	_, err := conf.GetWithError("org_flag")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingOrganization)
}
