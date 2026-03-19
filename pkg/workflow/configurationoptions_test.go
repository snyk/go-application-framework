package workflow_test

import (
	"bytes"
	"log"
	"os"
	"testing"

	"github.com/snyk/go-application-framework/pkg/configuration/configresolver"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/workflow"
)

func newTestFlagSet() *pflag.FlagSet {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	fs.Bool("snyk_code_enabled", false, "Enable Snyk Code analysis")
	folderScope := string(configresolver.FolderScope)
	fs.Lookup("snyk_code_enabled").Annotations = map[string][]string{
		"config.scope":       {folderScope},
		"config.remoteKey":   {"snyk_code_enabled"},
		"config.displayName": {"Snyk Code"},
		"config.description": {"Enable Snyk Code security analysis"},
		"config.ideKey":      {"activateSnykCode"},
	}

	fs.String("api_endpoint", "", "API endpoint URL")
	machineScope := string(configresolver.MachineScope)
	fs.Lookup("api_endpoint").Annotations = map[string][]string{
		"config.scope":       {machineScope},
		"config.remoteKey":   {"api_endpoint"},
		"config.displayName": {"API Endpoint"},
		"config.description": {"Snyk API endpoint URL"},
		"config.ideKey":      {"endpoint"},
	}

	fs.String("reference_branch", "", "Reference branch for delta findings")
	fs.Lookup("reference_branch").Annotations = map[string][]string{
		"config.scope":       {folderScope},
		"config.displayName": {"Reference Branch"},
		"config.description": {"Branch used as baseline for net-new findings"},
	}

	return fs
}

func TestConfigurationOptionsImpl_ImplementsConfigurationOptionsMetaData(t *testing.T) {
	var opts workflow.ConfigurationOptions = workflow.ConfigurationOptionsFromFlagset(newTestFlagSet())
	var _ workflow.ConfigurationOptionsMetaData = opts
	require.True(t, true)
}

func TestConfigurationOptionsFromFlagset_WarnsOnColonInFlagName(t *testing.T) {
	fs := pflag.NewFlagSet("bad", pflag.ContinueOnError)
	fs.Bool("has:colon", false, "bad flag name")

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	opts := workflow.ConfigurationOptionsFromFlagset(fs)
	assert.NotNil(t, opts, "must still return a valid ConfigurationOptions")
	assert.Contains(t, buf.String(), `flag name "has:colon"`)
}

func TestConfigurationOptionsFromFlagset_NilFlagset(t *testing.T) {
	assert.Nil(t, workflow.ConfigurationOptionsFromFlagset(nil))
}

func TestConfigurationOptionsFromFlagset_AcceptsValidNames(t *testing.T) {
	fs := pflag.NewFlagSet("good", pflag.ContinueOnError)
	fs.Bool("valid_flag", false, "ok")
	fs.String("another-flag", "", "also ok")

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	opts := workflow.ConfigurationOptionsFromFlagset(fs)
	assert.NotNil(t, opts)
	assert.Empty(t, buf.String(), "no warnings expected for valid flag names")
}

func newTestConfigOpts() workflow.ConfigurationOptions {
	return workflow.ConfigurationOptionsFromFlagset(newTestFlagSet())
}

func TestGetConfigurationOptionAnnotation(t *testing.T) {
	opts := newTestConfigOpts()
	md, ok := opts.(workflow.ConfigurationOptionsMetaData)
	assert.True(t, ok)

	tests := []struct {
		name       string
		flagName   string
		annotation string
		wantVal    string
		wantFound  bool
	}{
		{"existing annotation", "snyk_code_enabled", "config.scope", "folder", true},
		{"missing annotation key", "snyk_code_enabled", "config.nonexistent", "", false},
		{"missing flag", "no_such_flag", "config.scope", "", false},
		{"flag without annotations", "reference_branch", "config.remoteKey", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			val, found := md.GetConfigurationOptionAnnotation(tc.flagName, tc.annotation)
			assert.Equal(t, tc.wantVal, val)
			assert.Equal(t, tc.wantFound, found)
		})
	}
}

func TestConfigurationOptionsByAnnotation(t *testing.T) {
	opts := newTestConfigOpts()
	md, ok := opts.(workflow.ConfigurationOptionsMetaData)
	assert.True(t, ok)

	tests := []struct {
		name       string
		annotation string
		value      string
		wantLen    int
	}{
		{"match machine scope", "config.scope", "machine", 1},
		{"match folder scope", "config.scope", "folder", 2},
		{"no match", "config.scope", "nonexistent", 0},
		{"no such annotation", "config.bogus", "anything", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := md.ConfigurationOptionsByAnnotation(tc.annotation, tc.value)
			assert.Equal(t, tc.wantLen, len(result))
		})
	}
}

func TestConfigurationOptionNameByAnnotation(t *testing.T) {
	opts := newTestConfigOpts()
	md, ok := opts.(workflow.ConfigurationOptionsMetaData)
	assert.True(t, ok)

	tests := []struct {
		name       string
		annotation string
		value      string
		wantName   string
		wantFound  bool
	}{
		{"find by ideKey", "config.ideKey", "activateSnykCode", "snyk_code_enabled", true},
		{"find by ideKey endpoint", "config.ideKey", "endpoint", "api_endpoint", true},
		{"no match", "config.ideKey", "nonexistent", "", false},
		{"no such annotation", "config.bogus", "anything", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, found := md.ConfigurationOptionNameByAnnotation(tc.annotation, tc.value)
			assert.Equal(t, tc.wantName, name)
			assert.Equal(t, tc.wantFound, found)
		})
	}
}

func TestGetConfigurationOptionType(t *testing.T) {
	opts := newTestConfigOpts()
	md, ok := opts.(workflow.ConfigurationOptionsMetaData)
	assert.True(t, ok)

	tests := []struct {
		name     string
		flagName string
		wantType string
	}{
		{"bool flag", "snyk_code_enabled", "bool"},
		{"string flag", "api_endpoint", "string"},
		{"nonexistent flag", "no_such_flag", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantType, md.GetConfigurationOptionType(tc.flagName))
		})
	}
}

func TestGetConfigurationOptionUsage(t *testing.T) {
	opts := newTestConfigOpts()
	md, ok := opts.(workflow.ConfigurationOptionsMetaData)
	assert.True(t, ok)

	tests := []struct {
		name     string
		flagName string
		wantUsge string
	}{
		{"existing flag", "snyk_code_enabled", "Enable Snyk Code analysis"},
		{"nonexistent flag", "no_such_flag", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.wantUsge, md.GetConfigurationOptionUsage(tc.flagName))
		})
	}
}

func TestConfigurationOptionsFromJson(t *testing.T) {
	assert.Nil(t, workflow.ConfigurationOptionsFromJson([]byte(`{}`)))
}

func TestJsonFromConfigurationOptions(t *testing.T) {
	opts := newTestConfigOpts()
	assert.Nil(t, workflow.JsonFromConfigurationOptions(opts))
}

func TestFlagsetFromConfigurationOptions_NonImpl(t *testing.T) {
	// Passing nil should return nil
	assert.Nil(t, workflow.FlagsetFromConfigurationOptions(nil))
}
