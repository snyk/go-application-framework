package machineid

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configtest"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

type isolatedMachine struct {
	home   string
	shared pathPair
	studio pathPair
}

func newIsolatedMachine(t *testing.T) isolatedMachine {
	t.Helper()
	configtest.IsolateEnvironmentForTest(t)

	m := isolatedMachine{
		home:   t.TempDir(),
		shared: newPerUserOnlySharedFilePaths(t),
		studio: pathPair{
			machineWide: filepath.Join(t.TempDir(), "studio-machine-wide", "device-id"),
			perUser:     filepath.Join(t.TempDir(), "studio-per-user", "device-id"),
		},
	}
	t.Setenv("HOME", m.home)
	t.Setenv("USERPROFILE", m.home)

	sharedFilePaths = func() pathPair { return m.shared }
	t.Cleanup(func() { sharedFilePaths = defaultSharedFilePaths })
	studioDeviceIDPaths = func() pathPair { return m.studio }
	t.Cleanup(func() { studioDeviceIDPaths = defaultStudioDeviceIDPaths })

	_, err := configuration.CreateConfigurationFile("snyk.json")
	require.NoError(t, err)
	return m
}

func newRun(t *testing.T, opts ...ResolveOption) configuration.Configuration {
	t.Helper()
	config := configuration.NewWithOpts(configuration.WithFiles("snyk"), configuration.WithAutomaticEnv())
	config.AddDefaultValue(configuration.MACHINE_ID, Resolve(opts...))
	return config
}

func machineID(t *testing.T, config configuration.Configuration) string {
	t.Helper()
	value, err := config.GetStringWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	return value
}

func (m isolatedMachine) snykJSON(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(m.home, ".config", "configstore", "snyk.json"))
	if os.IsNotExist(err) || len(data) == 0 {
		return map[string]any{}
	}
	require.NoError(t, err)
	var content map[string]any
	require.NoError(t, json.Unmarshal(data, &content))
	return content
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, content, 0o600))
}

func writeSharedFileAs(t *testing.T, path string, content map[string]any) {
	t.Helper()
	data, err := json.Marshal(content)
	require.NoError(t, err)
	writeFile(t, path, data)
}

func sharedFileContent(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var content map[string]any
	require.NoError(t, json.Unmarshal(data, &content))
	return content
}

func (m isolatedMachine) blockEverySharedFileLocation(t *testing.T) {
	t.Helper()
	writeFile(t, filepath.Dir(filepath.Dir(m.shared.perUser)), []byte("not a directory"))
}

func TestAcceptance_GeneratedIDIsStoredInTheSharedFile(t *testing.T) {
	m := newIsolatedMachine(t)

	id := machineID(t, newRun(t))

	require.True(t, valid(id))
	content := sharedFileContent(t, m.shared.perUser)
	require.Equal(t, id, content["machine_id"])
	require.Equal(t, "generated", content["identifier_source"])
}

func TestAcceptance_ExplicitIDWinsOverTheSharedFile(t *testing.T) {
	m := newIsolatedMachine(t)
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "from-shared-file"})
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "device-managed-id")

	require.Equal(t, "device-managed-id", machineID(t, newRun(t)))
}

func TestAcceptance_ExplicitIDLeavesAnInstallerWrittenSharedFileExactlyAsItWas(t *testing.T) {
	m := newIsolatedMachine(t)
	installerWritten := []byte(`{"schema_version":1,"machine_id":"C02Q7KHTGFWF","identifier_source":"serial",` +
		`"serial_number":"C02Q7KHTGFWF","scope":"user","first_seen_at":"2026-09-14T08:14:03Z",` +
		`"updated_at":"2026-09-14T08:14:03Z","writer":"ads-installer/0.1.42"}`)
	writeFile(t, m.shared.perUser, installerWritten)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "studio-device-id")

	require.Equal(t, "studio-device-id", machineID(t, newRun(t)))
	require.Equal(t, "studio-device-id", machineID(t, newRun(t)))

	onDisk, err := os.ReadFile(m.shared.perUser)
	require.NoError(t, err)
	require.Equal(t, string(installerWritten), string(onDisk), "an explicitly supplied id must be used but never written to the shared file")
}

func TestAcceptance_ExplicitIDDoesNotCreateASharedFile(t *testing.T) {
	m := newIsolatedMachine(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "device-managed-id")

	require.Equal(t, "device-managed-id", machineID(t, newRun(t)))

	require.NoFileExists(t, m.shared.perUser)
}

func TestAcceptance_ExplicitIDWinsOverAnIDResolvedOnAPreviousRun(t *testing.T) {
	newIsolatedMachine(t)
	previous := machineID(t, newRun(t))

	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "device-managed-id")

	require.NotEqual(t, "device-managed-id", previous)
	require.Equal(t, "device-managed-id", machineID(t, newRun(t)))
}

func TestAcceptance_ExplicitIDSetLaterInTheSameProcessWins(t *testing.T) {
	newIsolatedMachine(t)
	config := newRun(t)
	machineID(t, config)

	config.Set(configuration.CLIENT_MACHINE_ID, "device-managed-id")

	require.Equal(t, "device-managed-id", machineID(t, config))
}

func TestAcceptance_IDWrittenToTheSharedFileByAnotherProductIsPickedUpOnTheNextRun(t *testing.T) {
	m := newIsolatedMachine(t)
	machineID(t, newRun(t))

	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "from-another-product", "writer": "another-product"})

	require.Equal(t, "from-another-product", machineID(t, newRun(t)))
}

func TestAcceptance_NothingIsWrittenToSnykJSON(t *testing.T) {
	m := newIsolatedMachine(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "device-managed-id")
	machineID(t, newRun(t))
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "")
	machineID(t, newRun(t))

	for key := range m.snykJSON(t) {
		require.NotContains(t, key, "machine_id", "the machine id must only be stored in the shared machine-id file")
	}
}

func TestAcceptance_NoWritableSharedFileLocationGivesAnEmptyMachineID(t *testing.T) {
	m := newIsolatedMachine(t)
	m.blockEverySharedFileLocation(t)
	config := newRun(t)

	require.Empty(t, machineID(t, config), "an id that cannot be stored is not a stable machine id")
	require.Empty(t, machineID(t, config))
}

func TestAcceptance_ExplicitIDIsReturnedEvenWhenTheSharedFileCannotBeWritten(t *testing.T) {
	m := newIsolatedMachine(t)
	m.blockEverySharedFileLocation(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "device-managed-id")

	require.Equal(t, "device-managed-id", machineID(t, newRun(t)))
}

func TestAcceptance_InvalidExplicitIDIsIgnored(t *testing.T) {
	for name, raw := range map[string]string{
		"trailing newline":   "device-managed-id\n",
		"brace-wrapped guid": "{550E8400-E29B-41D4-A716-446655440000}",
		"whitespace only":    "   ",
	} {
		t.Run(name, func(t *testing.T) {
			m := newIsolatedMachine(t)
			t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", raw)

			id := machineID(t, newRun(t))

			require.True(t, valid(id))
			require.Equal(t, "generated", sharedFileContent(t, m.shared.perUser)["identifier_source"])
		})
	}
}

func TestAcceptance_StudioDeviceIDIsAdoptedUnchangedAndWrittenToTheSharedFile(t *testing.T) {
	m := newIsolatedMachine(t)
	writeFile(t, m.studio.perUser, []byte("studio-device-id\n"))

	require.Equal(t, "studio-device-id", machineID(t, newRun(t)))

	content := sharedFileContent(t, m.shared.perUser)
	require.Equal(t, "studio-device-id", content["machine_id"])
	require.Equal(t, "persisted", content["identifier_source"])
	require.Equal(t, "go-application-framework", content["writer"])
	studio, err := os.ReadFile(m.studio.perUser)
	require.NoError(t, err)
	require.Equal(t, "studio-device-id\n", string(studio), "the Studio file must be left in place")
}

func TestAcceptance_MachineScopeStudioDeviceIDWinsWhenScopesDisagree(t *testing.T) {
	m := newIsolatedMachine(t)
	writeFile(t, m.studio.machineWide, []byte("machine-scope-id"))
	writeFile(t, m.studio.perUser, []byte("user-scope-id"))

	require.Equal(t, "machine-scope-id", machineID(t, newRun(t)))
}

func TestAcceptance_SharedFileWinsOverStudioDeviceID(t *testing.T) {
	m := newIsolatedMachine(t)
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "from-shared-file"})
	writeFile(t, m.studio.machineWide, []byte("studio-device-id"))

	require.Equal(t, "from-shared-file", machineID(t, newRun(t)))
}

func TestAcceptance_StudioDeviceIDIsReturnedEvenWhenTheSharedFileCannotBeWritten(t *testing.T) {
	m := newIsolatedMachine(t)
	m.blockEverySharedFileLocation(t)
	writeFile(t, m.studio.perUser, []byte("studio-device-id"))

	require.Equal(t, "studio-device-id", machineID(t, newRun(t)))
}

func TestAcceptance_InvalidStudioDeviceIDIsIgnoredAndLogged(t *testing.T) {
	m := newIsolatedMachine(t)
	writeFile(t, m.studio.perUser, []byte(" \t{ABC-99}\x00WEIRD-interior\n\n"))
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	id := machineID(t, newRun(t, WithLogger(&logger)))

	require.True(t, valid(id))
	require.Equal(t, "generated", sharedFileContent(t, m.shared.perUser)["identifier_source"])
	require.Contains(t, logs.String(), jsonEscapedPath(t, m.studio.perUser))
}

func TestAcceptance_RepeatedLookupsInOneProcessDoNotReadTheSharedFileAgain(t *testing.T) {
	m := newIsolatedMachine(t)
	config := newRun(t)
	first := machineID(t, config)

	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "changed-on-disk"})

	require.Equal(t, first, machineID(t, config))
	require.Equal(t, first, machineID(t, config.Clone()))
}

func TestAcceptance_SharedFileRecordsTheWriter(t *testing.T) {
	m := newIsolatedMachine(t)

	machineID(t, newRun(t))

	require.Equal(t, "go-application-framework", sharedFileContent(t, m.shared.perUser)["writer"])
}
