package configresolver_test

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// newTestFlagSet returns a flagset with org-, machine-, and folder-scoped flags.
func newTestFlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)

	fs.Bool("snyk_code_enabled", false, "Enable Snyk Code analysis")
	fs.Lookup("snyk_code_enabled").Annotations = map[string][]string{
		configresolver.AnnotationScope:     {"org"},
		configresolver.AnnotationRemoteKey: {"snyk_code_enabled"},
	}

	fs.String("api_endpoint", "", "API endpoint URL")
	fs.Lookup("api_endpoint").Annotations = map[string][]string{
		configresolver.AnnotationScope:     {"machine"},
		configresolver.AnnotationRemoteKey: {"api_endpoint"},
	}

	fs.String("reference_branch", "", "Reference branch for delta findings")
	fs.Lookup("reference_branch").Annotations = map[string][]string{
		configresolver.AnnotationScope: {"folder"},
	}

	fs.String("unscoped_flag", "", "Flag without scope annotation")

	return fs
}

func newResolver(conf configuration.Configuration, fs *pflag.FlagSet) *configresolver.Resolver {
	opts := workflow.ConfigurationOptionsFromFlagset(fs)
	md, _ := opts.(workflow.ConfigurationOptionsMetaData) //nolint:errcheck // test helper; panics on failure
	return configresolver.New(conf, md)
}

// ---------------------------------------------------------------------------
// prefix_keys.go
// ---------------------------------------------------------------------------

func TestPrefixKeys(t *testing.T) {
	tests := []struct {
		name     string
		fn       func() string
		expected string
	}{
		{"UserGlobalKey", func() string { return configresolver.UserGlobalKey("k") }, "user:global:k"},
		{"UserFolderKey", func() string { return configresolver.UserFolderKey("/proj", "k") }, "user:folder:/proj:k"},
		{"RemoteOrgKey", func() string { return configresolver.RemoteOrgKey("org1", "k") }, "remote:org1:k"},
		{"RemoteOrgFolderKey", func() string { return configresolver.RemoteOrgFolderKey("org1", "/proj", "k") }, "remote:org1:folder:/proj:k"},
		{"RemoteMachineKey", func() string { return configresolver.RemoteMachineKey("k") }, "remote:machine:k"},
		{"FolderMetadataKey", func() string { return configresolver.FolderMetadataKey("/proj", "preferred_org") }, "folder:/proj:preferred_org"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.fn())
		})
	}
}

// ---------------------------------------------------------------------------
// Resolve — nil fieldmap falls back to default
// ---------------------------------------------------------------------------

func TestResolve_NilFieldMap(t *testing.T) {
	conf := configuration.NewInMemory()
	conf.Set("k", "default-val")

	r := configresolver.New(conf, nil)
	val, src := r.Resolve("k", "org1", "/proj")
	assert.Equal(t, "default-val", val)
	assert.Equal(t, configresolver.ConfigSourceLocal, src)
}

// ---------------------------------------------------------------------------
// Resolve — unscoped flag falls through to default
// ---------------------------------------------------------------------------

func TestResolve_UnscopedFlag(t *testing.T) {
	fs := newTestFlagSet()
	conf := configuration.NewInMemory()
	conf.Set("unscoped_flag", "plain")

	r := newResolver(conf, fs)
	val, src := r.Resolve("unscoped_flag", "org1", "/proj")
	assert.Equal(t, "plain", val)
	assert.Equal(t, configresolver.ConfigSourceLocal, src)
}

// ---------------------------------------------------------------------------
// Machine scope
// ---------------------------------------------------------------------------

func TestResolveMachine(t *testing.T) {
	name := "api_endpoint"

	tests := []struct {
		name       string
		setup      func(conf configuration.Configuration)
		wantVal    any
		wantSource configresolver.ConfigSource
	}{
		{
			name:       "default value",
			setup:      func(conf configuration.Configuration) {},
			wantVal:    nil,
			wantSource: configresolver.ConfigSourceDefault,
		},
		{
			name: "remote unlocked",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.RemoteMachineKey(name), &configresolver.RemoteConfigField{Value: "remote-ep", IsLocked: false})
			},
			wantVal:    "remote-ep",
			wantSource: configresolver.ConfigSourceRemote,
		},
		{
			name: "user global overrides remote",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.RemoteMachineKey(name), &configresolver.RemoteConfigField{Value: "remote-ep", IsLocked: false})
				conf.Set(configresolver.UserGlobalKey(name), "user-ep")
			},
			wantVal:    "user-ep",
			wantSource: configresolver.ConfigSourceUserGlobal,
		},
		{
			name: "locked remote wins over user global",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.UserGlobalKey(name), "user-ep")
				conf.Set(configresolver.RemoteMachineKey(name), &configresolver.RemoteConfigField{Value: "locked-ep", IsLocked: true})
			},
			wantVal:    "locked-ep",
			wantSource: configresolver.ConfigSourceRemoteLocked,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFlagSet()
			conf := configuration.NewInMemory()
			tc.setup(conf)
			r := newResolver(conf, fs)

			val, src := r.Resolve(name, "org1", "")
			assert.Equal(t, tc.wantVal, val)
			assert.Equal(t, tc.wantSource, src)
		})
	}
}

// ---------------------------------------------------------------------------
// Org scope
// ---------------------------------------------------------------------------

func TestResolveOrg(t *testing.T) {
	name := "snyk_code_enabled"
	org := "org1"
	folder := "/proj"

	tests := []struct {
		name       string
		setup      func(conf configuration.Configuration)
		folder     string
		wantVal    any
		wantSource configresolver.ConfigSource
	}{
		{
			name:       "default value",
			setup:      func(conf configuration.Configuration) {},
			folder:     folder,
			wantVal:    nil,
			wantSource: configresolver.ConfigSourceDefault,
		},
		{
			name: "remote org unlocked",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.RemoteOrgKey(org, name), &configresolver.RemoteConfigField{Value: true, IsLocked: false})
			},
			folder:     "",
			wantVal:    true,
			wantSource: configresolver.ConfigSourceRemote,
		},
		{
			name: "remote folder unlocked takes precedence over remote org",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.RemoteOrgKey(org, name), &configresolver.RemoteConfigField{Value: true, IsLocked: false})
				conf.Set(configresolver.RemoteOrgFolderKey(org, folder, name), &configresolver.RemoteConfigField{Value: false, IsLocked: false})
			},
			folder:     folder,
			wantVal:    false,
			wantSource: configresolver.ConfigSourceRemote,
		},
		{
			name: "user global overrides remote",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.RemoteOrgKey(org, name), &configresolver.RemoteConfigField{Value: true, IsLocked: false})
				conf.Set(configresolver.UserGlobalKey(name), "user-global-val")
			},
			folder:     folder,
			wantVal:    "user-global-val",
			wantSource: configresolver.ConfigSourceUserGlobal,
		},
		{
			name: "user folder override with Changed=true",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.RemoteOrgKey(org, name), &configresolver.RemoteConfigField{Value: true, IsLocked: false})
				conf.Set(configresolver.UserGlobalKey(name), "user-global-val")
				conf.Set(configresolver.UserFolderKey(folder, name), &configresolver.LocalConfigField{Value: "folder-override", Changed: true})
			},
			folder:     folder,
			wantVal:    "folder-override",
			wantSource: configresolver.ConfigSourceUserFolderOverride,
		},
		{
			name: "user folder override with Changed=false is skipped",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.UserFolderKey(folder, name), &configresolver.LocalConfigField{Value: "not-active", Changed: false})
				conf.Set(configresolver.UserGlobalKey(name), "user-global-val")
			},
			folder:     folder,
			wantVal:    "user-global-val",
			wantSource: configresolver.ConfigSourceUserGlobal,
		},
		{
			name: "locked remote org wins over everything",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.UserGlobalKey(name), "user-val")
				conf.Set(configresolver.UserFolderKey(folder, name), &configresolver.LocalConfigField{Value: "folder-val", Changed: true})
				conf.Set(configresolver.RemoteOrgKey(org, name), &configresolver.RemoteConfigField{Value: "locked", IsLocked: true})
			},
			folder:     folder,
			wantVal:    "locked",
			wantSource: configresolver.ConfigSourceRemoteLocked,
		},
		{
			name: "locked remote folder wins over everything",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.UserGlobalKey(name), "user-val")
				conf.Set(configresolver.RemoteOrgKey(org, name), &configresolver.RemoteConfigField{Value: "org-unlocked", IsLocked: false})
				conf.Set(configresolver.RemoteOrgFolderKey(org, folder, name), &configresolver.RemoteConfigField{Value: "folder-locked", IsLocked: true})
			},
			folder:     folder,
			wantVal:    "folder-locked",
			wantSource: configresolver.ConfigSourceRemoteLocked,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFlagSet()
			conf := configuration.NewInMemory()
			tc.setup(conf)
			r := newResolver(conf, fs)

			val, src := r.Resolve(name, org, tc.folder)
			assert.Equal(t, tc.wantVal, val)
			assert.Equal(t, tc.wantSource, src)
		})
	}
}

// ---------------------------------------------------------------------------
// Folder scope
// ---------------------------------------------------------------------------

func TestResolveFolder(t *testing.T) {
	name := "reference_branch"
	org := "org1"
	folder := "/proj"

	tests := []struct {
		name       string
		setup      func(conf configuration.Configuration)
		folder     string
		wantVal    any
		wantSource configresolver.ConfigSource
	}{
		{
			name:       "default value",
			setup:      func(conf configuration.Configuration) {},
			folder:     folder,
			wantVal:    nil,
			wantSource: configresolver.ConfigSourceDefault,
		},
		{
			name: "remote org unlocked",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.RemoteOrgKey(org, name), &configresolver.RemoteConfigField{Value: "main", IsLocked: false})
			},
			folder:     folder,
			wantVal:    "main",
			wantSource: configresolver.ConfigSourceRemote,
		},
		{
			name: "remote folder unlocked takes precedence over remote org",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.RemoteOrgKey(org, name), &configresolver.RemoteConfigField{Value: "main", IsLocked: false})
				conf.Set(configresolver.RemoteOrgFolderKey(org, folder, name), &configresolver.RemoteConfigField{Value: "develop", IsLocked: false})
			},
			folder:     folder,
			wantVal:    "develop",
			wantSource: configresolver.ConfigSourceRemote,
		},
		{
			name: "folder value overrides remote",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.RemoteOrgKey(org, name), &configresolver.RemoteConfigField{Value: "main", IsLocked: false})
				conf.Set(configresolver.UserFolderKey(folder, name), &configresolver.LocalConfigField{Value: "my-branch", Changed: true})
			},
			folder:     folder,
			wantVal:    "my-branch",
			wantSource: configresolver.ConfigSourceFolder,
		},
		{
			name: "folder value Changed=false is skipped, falls to remote",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.RemoteOrgKey(org, name), &configresolver.RemoteConfigField{Value: "main", IsLocked: false})
				conf.Set(configresolver.UserFolderKey(folder, name), &configresolver.LocalConfigField{Value: "no", Changed: false})
			},
			folder:     folder,
			wantVal:    "main",
			wantSource: configresolver.ConfigSourceRemote,
		},
		{
			name: "user global when no remote and no folder",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.UserGlobalKey(name), "global-branch")
			},
			folder:     folder,
			wantVal:    "global-branch",
			wantSource: configresolver.ConfigSourceUserGlobal,
		},
		{
			name: "locked remote org wins",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.UserGlobalKey(name), "global")
				conf.Set(configresolver.UserFolderKey(folder, name), &configresolver.LocalConfigField{Value: "local", Changed: true})
				conf.Set(configresolver.RemoteOrgKey(org, name), &configresolver.RemoteConfigField{Value: "locked-org", IsLocked: true})
			},
			folder:     folder,
			wantVal:    "locked-org",
			wantSource: configresolver.ConfigSourceRemoteLocked,
		},
		{
			name: "locked remote folder wins over locked org",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.RemoteOrgKey(org, name), &configresolver.RemoteConfigField{Value: "locked-org", IsLocked: true})
				conf.Set(configresolver.RemoteOrgFolderKey(org, folder, name), &configresolver.RemoteConfigField{Value: "locked-folder", IsLocked: true})
			},
			folder:     folder,
			wantVal:    "locked-folder",
			wantSource: configresolver.ConfigSourceRemoteLocked,
		},
		{
			name: "empty folder path skips folder lookups",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.RemoteOrgKey(org, name), &configresolver.RemoteConfigField{Value: "org-val", IsLocked: false})
			},
			folder:     "",
			wantVal:    "org-val",
			wantSource: configresolver.ConfigSourceRemote,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFlagSet()
			conf := configuration.NewInMemory()
			tc.setup(conf)
			r := newResolver(conf, fs)

			val, src := r.Resolve(name, org, tc.folder)
			assert.Equal(t, tc.wantVal, val)
			assert.Equal(t, tc.wantSource, src)
		})
	}
}

// ---------------------------------------------------------------------------
// ResolveBool
// ---------------------------------------------------------------------------

func TestResolveBool(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		expected bool
	}{
		{"nil value", nil, false},
		{"true bool", true, true},
		{"false bool", false, false},
		{"string true", "true", true},
		{"string 1", "1", true},
		{"string false", "false", false},
		{"string invalid", "notabool", false},
		{"int nonzero", 42, true},
		{"int zero", 0, false},
		{"int64 nonzero", int64(1), true},
		{"int64 zero", int64(0), false},
		{"float64 nonzero", float64(3.14), true},
		{"float64 zero", float64(0), false},
		{"uint via reflect", uint(5), true},
		{"uint zero via reflect", uint(0), false},
		{"int8 via reflect", int8(1), true},
		{"int8 zero via reflect", int8(0), false},
		{"float32 via reflect", float32(1.0), true},
		{"float32 zero via reflect", float32(0), false},
		{"unsupported type", struct{}{}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFlagSet()
			conf := configuration.NewInMemory()
			name := "snyk_code_enabled"
			if tc.value != nil {
				conf.Set(configresolver.RemoteOrgKey("org1", name), &configresolver.RemoteConfigField{Value: tc.value, IsLocked: false})
			}
			r := newResolver(conf, fs)
			got := r.ResolveBool(name, "org1", "")
			assert.Equal(t, tc.expected, got)
		})
	}
}

// ---------------------------------------------------------------------------
// IsLocked
// ---------------------------------------------------------------------------

func TestIsLocked(t *testing.T) {
	name := "snyk_code_enabled"
	org := "org1"
	folder := "/proj"

	tests := []struct {
		name       string
		setup      func(conf configuration.Configuration)
		folderPath []string
		expected   bool
	}{
		{
			name:     "not locked when nothing set",
			setup:    func(conf configuration.Configuration) {},
			expected: false,
		},
		{
			name: "locked at org level",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.RemoteOrgKey(org, name), &configresolver.RemoteConfigField{Value: true, IsLocked: true})
			},
			expected: true,
		},
		{
			name: "not locked at org level",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.RemoteOrgKey(org, name), &configresolver.RemoteConfigField{Value: true, IsLocked: false})
			},
			expected: false,
		},
		{
			name: "locked at folder level for org-scope flag",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.RemoteOrgKey(org, name), &configresolver.RemoteConfigField{Value: true, IsLocked: false})
				conf.Set(configresolver.RemoteOrgFolderKey(org, folder, name), &configresolver.RemoteConfigField{Value: false, IsLocked: true})
			},
			folderPath: []string{folder},
			expected:   true,
		},
		{
			name: "machine-scope ignores folder lock check",
			setup: func(conf configuration.Configuration) {
				conf.Set(configresolver.RemoteMachineKey("api_endpoint"), &configresolver.RemoteConfigField{Value: "ep", IsLocked: true})
			},
			folderPath: []string{folder},
			expected:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFlagSet()
			conf := configuration.NewInMemory()
			tc.setup(conf)
			r := newResolver(conf, fs)

			flagName := name
			if tc.name == "machine-scope ignores folder lock check" {
				flagName = "api_endpoint"
			}

			got := r.IsLocked(flagName, org, tc.folderPath...)
			assert.Equal(t, tc.expected, got)
		})
	}
}

// ---------------------------------------------------------------------------
// fallback — ConfigSourceLocal vs ConfigSourceDefault
// ---------------------------------------------------------------------------

func TestResolve_FallbackSourceLocal(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(conf configuration.Configuration)
		wantVal    any
		wantSource configresolver.ConfigSource
	}{
		{
			name:       "unset key returns ConfigSourceDefault",
			setup:      func(conf configuration.Configuration) {},
			wantVal:    nil,
			wantSource: configresolver.ConfigSourceDefault,
		},
		{
			name: "explicitly Set key returns ConfigSourceLocal",
			setup: func(conf configuration.Configuration) {
				conf.Set("api_endpoint", "https://custom.api")
			},
			wantVal:    "https://custom.api",
			wantSource: configresolver.ConfigSourceLocal,
		},
		{
			name: "env var via AutomaticEnv returns ConfigSourceLocal",
			setup: func(conf configuration.Configuration) {
				// AutomaticEnv is already enabled via NewInMemory
			},
			wantVal:    "https://env.api",
			wantSource: configresolver.ConfigSourceLocal,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "env var via AutomaticEnv returns ConfigSourceLocal" {
				t.Setenv("API_ENDPOINT", "https://env.api")
			}
			fs := newTestFlagSet()
			conf := configuration.NewInMemory()
			tc.setup(conf)
			r := newResolver(conf, fs)

			val, src := r.Resolve("api_endpoint", "org1", "")
			assert.Equal(t, tc.wantVal, val)
			assert.Equal(t, tc.wantSource, src)
		})
	}
}

// ---------------------------------------------------------------------------
// remoteField / localField — wrong type returns nil (via Resolve fallback)
// ---------------------------------------------------------------------------

func TestResolve_WrongTypeStoredAtRemoteKey(t *testing.T) {
	fs := newTestFlagSet()
	conf := configuration.NewInMemory()
	// Store a plain string where a *RemoteConfigField is expected
	conf.Set(configresolver.RemoteOrgKey("org1", "snyk_code_enabled"), "not-a-remote-field")
	r := newResolver(conf, fs)

	val, src := r.Resolve("snyk_code_enabled", "org1", "")
	assert.Equal(t, configresolver.ConfigSourceDefault, src)
	assert.Nil(t, val)
}

func TestResolve_WrongTypeStoredAtLocalKey(t *testing.T) {
	fs := newTestFlagSet()
	conf := configuration.NewInMemory()
	// Store a plain string where a *LocalConfigField is expected at the user folder key
	conf.Set(configresolver.UserFolderKey("/proj", "snyk_code_enabled"), "not-a-local-field")
	r := newResolver(conf, fs)

	val, src := r.Resolve("snyk_code_enabled", "org1", "/proj")
	assert.Equal(t, configresolver.ConfigSourceDefault, src)
	assert.Nil(t, val)
}

// ---------------------------------------------------------------------------
// isUserSet — keyDeleted marker treated as not set
// ---------------------------------------------------------------------------

func TestResolve_LocalFieldNilValue(t *testing.T) {
	fs := newTestFlagSet()
	conf := configuration.NewInMemory()
	// UserFolderKey is set but the value is nil — localField should return nil
	conf.Set(configresolver.UserFolderKey("/proj", "reference_branch"), nil)
	r := newResolver(conf, fs)

	val, src := r.Resolve("reference_branch", "org1", "/proj")
	assert.Equal(t, configresolver.ConfigSourceDefault, src)
	assert.Nil(t, val)
}

func TestResolve_UserGlobalKeyDeleted(t *testing.T) {
	fs := newTestFlagSet()
	conf := configuration.NewInMemory()
	// Unset marks with keyDeleted internally; simulate by using Unset
	conf.Set(configresolver.UserGlobalKey("api_endpoint"), "val")
	conf.Unset(configresolver.UserGlobalKey("api_endpoint"))

	r := newResolver(conf, fs)
	val, src := r.Resolve("api_endpoint", "org1", "")
	// Should fall through to default since the user global key is deleted
	assert.Equal(t, configresolver.ConfigSourceDefault, src)
	_ = val
}
