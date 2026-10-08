package machineid

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	configtest.IsolateEnvironmentForTest(t, "SNYK_API", "INTERNAL_SNYK_CLIENT_MACHINE_ID")

	m := isolatedMachine{
		home:   t.TempDir(),
		shared: tempPaths(t),
		studio: pathPair{
			machineWide: filepath.Join(t.TempDir(), "studio-machine-wide", "device-id"),
			perUser:     filepath.Join(t.TempDir(), "studio-per-user", "device-id"),
		},
	}
	t.Setenv("HOME", m.home)
	t.Setenv("USERPROFILE", m.home)

	_, err := configuration.CreateConfigurationFile("snyk.json")
	require.NoError(t, err)
	return m
}

// newRun starts a separate run on m, as a new process would.
func (m isolatedMachine) newRun(opts ...ResolveOption) configuration.Configuration {
	config := configuration.NewWithOpts(configuration.WithFiles("snyk"), configuration.WithAutomaticEnv())
	config.AddDefaultValue(configuration.MACHINE_ID, m.resolve(opts...))
	return config
}

func (m isolatedMachine) resolve(opts ...ResolveOption) configuration.DefaultValueFunction {
	return Resolve(append([]ResolveOption{withPaths(m.shared, m.studio)}, opts...)...)
}

func machineID(t *testing.T, config configuration.Configuration) string {
	t.Helper()
	value, err := config.GetStringWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	return value
}

// snykJSON returns the contents of the configuration file newIsolatedMachine creates.
func (m isolatedMachine) snykJSON(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(m.home, ".config", "configstore", "snyk.json"))
	require.NoError(t, err)
	return string(data)
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

	id := machineID(t, m.newRun())

	require.True(t, valid(id))
	content := sharedFileContent(t, m.shared.perUser)
	require.Equal(t, id, content["machine_id"])
	require.Equal(t, "generated", content["identifier_source"])
}

func TestAcceptance_GeneratedIDIsReturnedAgainOnTheNextRun(t *testing.T) {
	m := newIsolatedMachine(t)
	first := machineID(t, m.newRun())

	require.True(t, valid(first))
	require.Equal(t, first, machineID(t, m.newRun()))
}

func TestAcceptance_ExplicitIDWinsOverTheSharedFile(t *testing.T) {
	m := newIsolatedMachine(t)
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "from-shared-file"})
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "device-managed-id")

	require.Equal(t, "device-managed-id", machineID(t, m.newRun()))
}

func TestAcceptance_ExplicitIDLeavesAnInstallerWrittenSharedFileExactlyAsItWas(t *testing.T) {
	m := newIsolatedMachine(t)
	installerWritten := []byte(`{"schema_version":1,"machine_id":"C02Q7KHTGFWF","identifier_source":"serial",` +
		`"serial_number":"C02Q7KHTGFWF","scope":"user","first_seen_at":"2026-09-14T08:14:03Z",` +
		`"updated_at":"2026-09-14T08:14:03Z","writer":"some-installer/1.0.0"}`)
	writeFile(t, m.shared.perUser, installerWritten)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "studio-device-id")

	require.Equal(t, "studio-device-id", machineID(t, m.newRun()))
	require.Equal(t, "studio-device-id", machineID(t, m.newRun()))

	onDisk, err := os.ReadFile(m.shared.perUser)
	require.NoError(t, err)
	require.Equal(t, string(installerWritten), string(onDisk), "an explicitly supplied id must be used but never written to the shared file")
}

func TestAcceptance_ExplicitIDDoesNotCreateASharedFile(t *testing.T) {
	m := newIsolatedMachine(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "device-managed-id")

	require.Equal(t, "device-managed-id", machineID(t, m.newRun()))

	require.NoFileExists(t, m.shared.perUser)
}

func TestAcceptance_ExplicitIDWinsOverAnIDResolvedOnAPreviousRun(t *testing.T) {
	m := newIsolatedMachine(t)
	previous := machineID(t, m.newRun())

	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "device-managed-id")

	require.NotEqual(t, "device-managed-id", previous)
	require.Equal(t, "device-managed-id", machineID(t, m.newRun()))
}

func TestAcceptance_ExplicitIDSetAfterTheFirstLookupIsUsedFromTheNextRun(t *testing.T) {
	m := newIsolatedMachine(t)
	config := m.newRun()
	first := machineID(t, config)

	config.Set(configuration.CLIENT_MACHINE_ID, "device-managed-id")

	require.Equal(t, first, machineID(t, config), "the machine id must not change within a process once read")
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "device-managed-id")
	require.Equal(t, "device-managed-id", machineID(t, m.newRun()), "a restarted process must use the explicit id")
}

func TestAcceptance_ExplicitIDSetAfterAFailedLookupIsUsed(t *testing.T) {
	m := newIsolatedMachine(t)
	m.blockEverySharedFileLocation(t)
	now := time.Now()
	config := m.newRun(withClock(func() time.Time { return now }))
	require.Empty(t, machineID(t, config))

	config.Set(configuration.CLIENT_MACHINE_ID, "device-managed-id")
	now = now.Add(retryDelay)

	require.Equal(t, "device-managed-id", machineID(t, config))
}

func TestAcceptance_AValueSetOnMachineIDIsReturnedAsIs(t *testing.T) {
	m := newIsolatedMachine(t)
	config := m.newRun()

	config.Set(configuration.MACHINE_ID, "set-by-host")

	require.Equal(t, "set-by-host", machineID(t, config))
	require.NoFileExists(t, m.shared.perUser, "a set value must not trigger resolution")
}

func TestAcceptance_IDWrittenToTheSharedFileByAnotherProductIsPickedUpOnTheNextRun(t *testing.T) {
	m := newIsolatedMachine(t)
	machineID(t, m.newRun())

	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "from-another-product", "writer": "another-product"})

	require.Equal(t, "from-another-product", machineID(t, m.newRun()))
}

func TestAcceptance_NothingIsWrittenToSnykJSON(t *testing.T) {
	m := newIsolatedMachine(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "device-managed-id")
	explicit := machineID(t, m.newRun())
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "")
	generated := machineID(t, m.newRun())

	require.Equal(t, "device-managed-id", explicit)
	require.Equal(t, generated, sharedFileContent(t, m.shared.perUser)["machine_id"])
	content := m.snykJSON(t)
	for _, id := range []string{explicit, generated} {
		require.NotContains(t, content, id, "the machine id must only be stored in the shared machine-id file")
	}
}

func TestAcceptance_NoWritableSharedFileLocationGivesAnEmptyMachineID(t *testing.T) {
	m := newIsolatedMachine(t)
	m.blockEverySharedFileLocation(t)
	config := m.newRun()

	require.Empty(t, machineID(t, config), "an id that cannot be stored is not a stable machine id")
	require.Empty(t, machineID(t, config))
}

func TestAcceptance_WriteFailuresAreLoggedWithTheirCause(t *testing.T) {
	for name, seedStudio := range map[string]bool{"generated id": false, "Snyk Studio id": true} {
		t.Run(name, func(t *testing.T) {
			m := newIsolatedMachine(t)
			m.blockEverySharedFileLocation(t)
			if seedStudio {
				writeFile(t, m.studio.perUser, []byte("studio-device-id"))
			}
			var logs bytes.Buffer
			logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

			machineID(t, m.newRun(WithLogger(&logger)))

			line := logLineContaining(t, logs.String(), "could not be stored")
			require.Contains(t, line, `"error":`)
			blocked := filepath.Dir(filepath.Dir(m.shared.perUser))
			require.Contains(t, line, jsonEscaped(t, blocked), "the per-user failure must be logged, not just the machine-wide one")
		})
	}
}

func logLineContaining(t *testing.T, logs, substr string) string {
	t.Helper()
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, substr) {
			return line
		}
	}
	t.Fatalf("no log line contains %q:\n%s", substr, logs)
	return ""
}

func TestAcceptance_AFailedWriteIsRetriedAfterTheRetryDelay(t *testing.T) {
	m := newIsolatedMachine(t)
	blocker := filepath.Dir(filepath.Dir(m.shared.perUser))
	m.blockEverySharedFileLocation(t)
	now := time.Now()
	config := m.newRun(withClock(func() time.Time { return now }))
	require.Empty(t, machineID(t, config))
	require.NoError(t, os.Remove(blocker))

	now = now.Add(retryDelay - time.Second)
	require.Empty(t, machineID(t, config), "a lookup within the retry delay must not touch the disk again")
	require.NoFileExists(t, m.shared.perUser)

	now = now.Add(time.Second)
	id := machineID(t, config)

	require.True(t, valid(id), "once the shared file can be written, the same process must get a stable id")
	require.Equal(t, id, sharedFileContent(t, m.shared.perUser)["machine_id"])
	require.Equal(t, id, machineID(t, config))
}

func TestAcceptance_ExplicitIDIsReturnedEvenWhenTheSharedFileCannotBeWritten(t *testing.T) {
	m := newIsolatedMachine(t)
	m.blockEverySharedFileLocation(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "device-managed-id")

	require.Equal(t, "device-managed-id", machineID(t, m.newRun()))
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

			id := machineID(t, m.newRun())

			require.True(t, valid(id))
			require.Equal(t, "generated", sharedFileContent(t, m.shared.perUser)["identifier_source"])
		})
	}
}

func TestAcceptance_StudioDeviceIDIsAdoptedUnchangedAndWrittenToTheSharedFile(t *testing.T) {
	m := newIsolatedMachine(t)
	writeFile(t, m.studio.perUser, []byte("studio-device-id\n"))

	require.Equal(t, "studio-device-id", machineID(t, m.newRun()))

	content := sharedFileContent(t, m.shared.perUser)
	require.Equal(t, "studio-device-id", content["machine_id"])
	require.Equal(t, "persisted", content["identifier_source"])
	require.Equal(t, "go-application-framework", content["writer"])
	studio, err := os.ReadFile(m.studio.perUser)
	require.NoError(t, err)
	require.Equal(t, "studio-device-id\n", string(studio), "the Studio file must be left in place")
}

func TestAcceptance_AdoptedStudioDeviceIDIsReturnedAgainAfterTheStudioFileChanges(t *testing.T) {
	m := newIsolatedMachine(t)
	writeFile(t, m.studio.perUser, []byte("studio-device-id"))
	require.Equal(t, "studio-device-id", machineID(t, m.newRun()))

	writeFile(t, m.studio.perUser, []byte("changed-studio-device-id"))
	require.Equal(t, "studio-device-id", machineID(t, m.newRun()), "once adopted, the id comes from the shared file")

	require.NoError(t, os.Remove(m.studio.perUser))
	require.Equal(t, "studio-device-id", machineID(t, m.newRun()))
}

func TestAcceptance_MachineScopeStudioDeviceIDWinsWhenScopesDisagree(t *testing.T) {
	m := newIsolatedMachine(t)
	writeFile(t, m.studio.machineWide, []byte("machine-scope-id"))
	writeFile(t, m.studio.perUser, []byte("user-scope-id"))

	require.Equal(t, "machine-scope-id", machineID(t, m.newRun()))
}

func TestAcceptance_SharedFileWinsOverStudioDeviceID(t *testing.T) {
	m := newIsolatedMachine(t)
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "from-shared-file"})
	writeFile(t, m.studio.machineWide, []byte("studio-device-id"))

	require.Equal(t, "from-shared-file", machineID(t, m.newRun()))
}

func TestAcceptance_StudioDeviceIDIsReturnedEvenWhenTheSharedFileCannotBeWritten(t *testing.T) {
	m := newIsolatedMachine(t)
	m.blockEverySharedFileLocation(t)
	writeFile(t, m.studio.perUser, []byte("studio-device-id"))

	require.Equal(t, "studio-device-id", machineID(t, m.newRun()))
}

func TestAcceptance_InvalidStudioDeviceIDIsIgnoredAndLogged(t *testing.T) {
	m := newIsolatedMachine(t)
	writeFile(t, m.studio.perUser, []byte(" \t{ABC-99}\x00WEIRD-interior\n\n"))
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	id := machineID(t, m.newRun(WithLogger(&logger)))

	require.True(t, valid(id))
	require.Equal(t, "generated", sharedFileContent(t, m.shared.perUser)["identifier_source"])
	require.Contains(t, logs.String(), jsonEscaped(t, m.studio.perUser))
}

func TestAcceptance_RepeatedLookupsInOneProcessDoNotReadTheSharedFileAgain(t *testing.T) {
	m := newIsolatedMachine(t)
	config := m.newRun()
	first := machineID(t, config)

	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "changed-on-disk"})

	require.Equal(t, first, machineID(t, config))
	require.Equal(t, first, machineID(t, config.Clone()))
}

func TestAcceptance_SharedFileRecordsTheWriter(t *testing.T) {
	m := newIsolatedMachine(t)

	machineID(t, m.newRun())

	require.Equal(t, "go-application-framework", sharedFileContent(t, m.shared.perUser)["writer"])
}
