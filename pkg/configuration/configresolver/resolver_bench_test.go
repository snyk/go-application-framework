package configresolver_test

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	cr "github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func setupBench(b *testing.B) (configuration.Configuration, workflow.FlagMetadata) {
	b.Helper()
	fs := newFlagSetWithAnnotations()
	conf := configuration.NewWithOpts(
		configuration.WithSupportedEnvVars("NODE_EXTRA_CA_CERTS"),
		configuration.WithSupportedEnvVarPrefixes("snyk_", "internal_", "test_"),
	)
	require.NoError(b, conf.AddFlagSet(fs))
	fm := workflow.NewConfigurationOptionsStore(workflow.ConfigurationOptionsFromFlagset(fs))
	return conf, fm
}

func setupBenchWithCache(b *testing.B) (configuration.Configuration, workflow.FlagMetadata) {
	b.Helper()
	fs := newFlagSetWithAnnotations()
	conf := configuration.NewWithOpts(
		configuration.WithSupportedEnvVars("NODE_EXTRA_CA_CERTS"),
		configuration.WithSupportedEnvVarPrefixes("snyk_", "internal_", "test_"),
		configuration.WithCachingEnabled(configuration.NoCacheExpiration),
	)
	require.NoError(b, conf.AddFlagSet(fs))
	fm := workflow.NewConfigurationOptionsStore(workflow.ConfigurationOptionsFromFlagset(fs))
	return conf, fm
}

func addRemoteConfig(conf configuration.Configuration) {
	const orgID = "org123"
	const folderPath = "/workspace/project"
	conf.Set(cr.RemoteOrgKey(orgID, "snyk_code_enabled"), &cr.RemoteConfigField{Value: true})
	conf.Set(cr.RemoteMachineKey("api_endpoint"), &cr.RemoteConfigField{Value: "https://api.snyk.io"})
	conf.Set(cr.RemoteOrgFolderKey(orgID, folderPath, "reference_branch"), &cr.RemoteConfigField{Value: "main"})
	conf.Set(cr.UserGlobalKey("snyk_code_enabled"), true)
}

func addManyFlags(fs *pflag.FlagSet, n int) {
	for i := range n {
		name := "extra_flag_" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		fs.String(name, "", "extra flag")
		fs.Lookup(name).Annotations = map[string][]string{
			cr.AnnotationScope: {"org"},
		}
	}
}

func BenchmarkResolve_OrgScope(b *testing.B) {
	conf, fm := setupBench(b)
	addRemoteConfig(conf)
	resolver := cr.New(conf, fm)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		resolver.Resolve("snyk_code_enabled", "org123", "/workspace/project")
	}
}

func BenchmarkResolve_OrgScope_WithCache(b *testing.B) {
	conf, fm := setupBenchWithCache(b)
	addRemoteConfig(conf)
	resolver := cr.New(conf, fm)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		resolver.Resolve("snyk_code_enabled", "org123", "/workspace/project")
	}
}

func BenchmarkResolve_FolderScope(b *testing.B) {
	conf, fm := setupBench(b)
	addRemoteConfig(conf)
	resolver := cr.New(conf, fm)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		resolver.Resolve("reference_branch", "org123", "/workspace/project")
	}
}

func BenchmarkResolve_MachineScope(b *testing.B) {
	conf, fm := setupBench(b)
	addRemoteConfig(conf)
	resolver := cr.New(conf, fm)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		resolver.Resolve("api_endpoint", "org123", "/workspace/project")
	}
}

func BenchmarkResolve_ManyFlags(b *testing.B) {
	fs := newFlagSetWithAnnotations()
	addManyFlags(fs, 50)
	conf := configuration.NewWithOpts(
		configuration.WithSupportedEnvVars("NODE_EXTRA_CA_CERTS"),
		configuration.WithSupportedEnvVarPrefixes("snyk_", "internal_", "test_"),
	)
	require.NoError(b, conf.AddFlagSet(fs))
	fm := workflow.NewConfigurationOptionsStore(workflow.ConfigurationOptionsFromFlagset(fs))
	addRemoteConfig(conf)
	resolver := cr.New(conf, fm)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		resolver.Resolve("snyk_code_enabled", "org123", "/workspace/project")
	}
}

func BenchmarkIsSet_PrefixedKey(b *testing.B) {
	conf, _ := setupBench(b)
	key := cr.UserGlobalKey("snyk_code_enabled")
	conf.Set(key, true)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		conf.IsSet(key)
	}
}

func BenchmarkGet_PrefixedKey(b *testing.B) {
	conf, _ := setupBench(b)
	key := cr.RemoteOrgKey("org123", "snyk_code_enabled")
	conf.Set(key, &cr.RemoteConfigField{Value: true})

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		conf.Get(key)
	}
}

func BenchmarkGet_EnvVarKey(b *testing.B) {
	conf, _ := setupBench(b)
	conf.Set("snyk_code_enabled", true)

	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		conf.Get("snyk_code_enabled")
	}
}
