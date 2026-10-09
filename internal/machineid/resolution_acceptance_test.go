package machineid

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configtest"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
)

type isolatedMachine struct {
	home   string
	shared pathPair
	studio pathPair
}

func newIsolatedMachine(t *testing.T) isolatedMachine {
	t.Helper()
	configtest.IsolateEnvironmentForTest(t, "SNYK_API", "INTERNAL_SNYK_MACHINE_ID", "INTERNAL_SNYK_CLIENT_MACHINE_ID")

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

// machineID reads MACHINE_ID, requiring runtimeinfo.ErrNoMachineID exactly when no id was found.
func machineID(t *testing.T, config configuration.Configuration) string {
	t.Helper()
	value, err := config.GetStringWithError(configuration.MACHINE_ID)
	if value == "" {
		require.ErrorIs(t, err, runtimeinfo.ErrNoMachineID)
	} else {
		require.NoError(t, err)
	}
	return value
}

// snykJSON returns the contents of the configuration file newIsolatedMachine creates.
func (m isolatedMachine) snykJSON(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(m.home, ".config", "configstore", "snyk.json"))
	require.NoError(t, err)
	return string(data)
}

func writeSharedFileAs(t *testing.T, path string, content map[string]any) {
	t.Helper()
	data, err := json.Marshal(content)
	require.NoError(t, err)
	seed(t, path, string(data))
}

func (m isolatedMachine) blockEverySharedFileLocation(t *testing.T) {
	t.Helper()
	seed(t, filepath.Dir(filepath.Dir(m.shared.perUser)), "not a directory")
}

func TestAcceptance_GeneratedIDIsStoredInTheSharedFile(t *testing.T) {
	m := newIsolatedMachine(t)

	id := machineID(t, m.newRun())

	require.True(t, valid(id))
	content := readFile(t, m.shared.perUser)
	require.Equal(t, id, content.MachineID)
	require.Equal(t, "generated", content.IdentifierSource)
}

func TestAcceptance_GeneratedIDIsReturnedAgainOnTheNextRun(t *testing.T) {
	m := newIsolatedMachine(t)
	first := machineID(t, m.newRun())

	require.True(t, valid(first))
	require.Equal(t, first, machineID(t, m.newRun()))
}

func TestAcceptance_SuppliedIDWinsOverTheSharedFile(t *testing.T) {
	m := newIsolatedMachine(t)
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "from-shared-file"})
	t.Setenv("INTERNAL_SNYK_MACHINE_ID", "supplied-id")

	require.Equal(t, "supplied-id", machineID(t, m.newRun()))
}

func TestAcceptance_SuppliedIDLeavesAnInstallerWrittenSharedFileExactlyAsItWas(t *testing.T) {
	m := newIsolatedMachine(t)
	installerWritten := `{"schema_version":1,"machine_id":"C02Q7KHTGFWF","identifier_source":"serial",` +
		`"serial_number":"C02Q7KHTGFWF","scope":"user","first_seen_at":"2026-09-14T08:14:03Z",` +
		`"updated_at":"2026-09-14T08:14:03Z","writer":"some-installer/1.0.0"}`
	seed(t, m.shared.perUser, installerWritten)
	t.Setenv("INTERNAL_SNYK_MACHINE_ID", "studio-device-id")

	require.Equal(t, "studio-device-id", machineID(t, m.newRun()))
	require.Equal(t, "studio-device-id", machineID(t, m.newRun()))

	onDisk, err := os.ReadFile(m.shared.perUser)
	require.NoError(t, err)
	require.Equal(t, installerWritten, string(onDisk), "a supplied id must be used but never written to the shared file")
}

func TestAcceptance_SuppliedIDWinsOverAnIDResolvedOnAPreviousRun(t *testing.T) {
	m := newIsolatedMachine(t)
	previous := machineID(t, m.newRun())

	t.Setenv("INTERNAL_SNYK_MACHINE_ID", "supplied-id")

	require.NotEqual(t, "supplied-id", previous)
	require.Equal(t, "supplied-id", machineID(t, m.newRun()))
}

func TestAcceptance_SuppliedIDSetAfterTheFirstLookupIsUsed(t *testing.T) {
	m := newIsolatedMachine(t)
	config := m.newRun()
	resolved := machineID(t, config)

	config.Set(configuration.MACHINE_ID, "supplied-id")

	require.Equal(t, "supplied-id", machineID(t, config), "a supplied value is returned as is")
	config.Unset(configuration.MACHINE_ID)
	require.Equal(t, resolved, machineID(t, config), "without a supplied value, the resolved id is kept")
}

func TestAcceptance_SuppliedIDSetAfterAFailedLookupIsUsed(t *testing.T) {
	m := newIsolatedMachine(t)
	m.blockEverySharedFileLocation(t)
	config := m.newRun()
	require.Empty(t, machineID(t, config))

	config.Set(configuration.MACHINE_ID, "supplied-id")

	require.Equal(t, "supplied-id", machineID(t, config))
}

func TestAcceptance_EachWayOfSupplyingMachineIDIsUsed(t *testing.T) {
	// Each supplier runs before or after the configuration is created, as it would in a host: the
	// environment and snyk.json are in place at start-up, a direct Set happens afterwards.
	for name, supply := range map[string]func(t *testing.T, m isolatedMachine) configuration.Configuration{
		"set directly": func(_ *testing.T, m isolatedMachine) configuration.Configuration {
			config := m.newRun()
			config.Set(configuration.MACHINE_ID, "supplied-id")
			return config
		},
		"environment variable": func(t *testing.T, m isolatedMachine) configuration.Configuration {
			t.Helper()
			t.Setenv("INTERNAL_SNYK_MACHINE_ID", "supplied-id")
			// Storage is blocked too: a supplied id must not depend on the shared file being writable.
			m.blockEverySharedFileLocation(t)
			return m.newRun()
		},
		"snyk.json": func(t *testing.T, m isolatedMachine) configuration.Configuration {
			t.Helper()
			seed(t, filepath.Join(m.home, ".config", "configstore", "snyk.json"), `{"`+configuration.MACHINE_ID+`":"supplied-id"}`)
			return m.newRun()
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := newIsolatedMachine(t)
			config := supply(t, m)

			require.Equal(t, "supplied-id", machineID(t, config))
			require.NoFileExists(t, m.shared.perUser, "a supplied id must never be written to the shared file")
		})
	}
}

func TestAcceptance_TheStudioCLIVariableAloneDoesNotSupplyTheMachineID(t *testing.T) {
	m := newIsolatedMachine(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "studio-cli-value")

	id := machineID(t, m.newRun())

	require.NotEqual(t, "studio-cli-value", id)
	require.Equal(t, id, readFile(t, m.shared.perUser).MachineID)
}

func TestAcceptance_IDWrittenToTheSharedFileByAnotherProductIsPickedUpOnTheNextRun(t *testing.T) {
	m := newIsolatedMachine(t)
	machineID(t, m.newRun())

	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "from-another-product", "writer": "another-product"})

	require.Equal(t, "from-another-product", machineID(t, m.newRun()))
}

func TestAcceptance_NothingIsWrittenToSnykJSON(t *testing.T) {
	m := newIsolatedMachine(t)
	t.Setenv("INTERNAL_SNYK_MACHINE_ID", "supplied-id")
	supplied := machineID(t, m.newRun())
	t.Setenv("INTERNAL_SNYK_MACHINE_ID", "")
	generated := machineID(t, m.newRun())

	require.Equal(t, "supplied-id", supplied)
	require.Equal(t, generated, readFile(t, m.shared.perUser).MachineID)
	content := m.snykJSON(t)
	for _, id := range []string{supplied, generated} {
		require.NotContains(t, content, id, "the machine id must only be stored in the shared machine-id file")
	}
}

func TestAcceptance_AFailedLookupIsRetriedWithOrWithoutConfigurationCaching(t *testing.T) {
	for name, opts := range map[string][]configuration.Opts{
		"caching off": nil,
		"caching on":  {configuration.WithCachingEnabled(configuration.NoCacheExpiration)},
	} {
		t.Run(name, func(t *testing.T) {
			m := newIsolatedMachine(t)
			blocker := filepath.Dir(filepath.Dir(m.shared.perUser))
			m.blockEverySharedFileLocation(t)
			config := configuration.NewWithOpts(append([]configuration.Opts{configuration.WithFiles("snyk"), configuration.WithAutomaticEnv()}, opts...)...)
			config.AddDefaultValue(configuration.MACHINE_ID, m.resolve())
			require.Empty(t, machineID(t, config))

			require.NoError(t, os.Remove(blocker))

			require.NotEmpty(t, machineID(t, config), "a failed lookup must not be cached, so it is retried")
		})
	}
}

func TestAcceptance_AnInvalidSuppliedValueIsLoggedAtDebugOnEachRead(t *testing.T) {
	m := newIsolatedMachine(t)
	m.blockEverySharedFileLocation(t)
	t.Setenv("INTERNAL_SNYK_MACHINE_ID", "not valid")
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	config := m.newRun(WithLogger(&logger))

	for range 3 {
		require.Empty(t, machineID(t, config))
	}

	require.Equal(t, 3, strings.Count(logs.String(), "supplied value failed validation"))
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "supplied value failed validation") {
			require.Contains(t, line, `"level":"debug"`, "a value checked on every read must not warn on every read")
		}
	}
}

func TestAcceptance_ANonStringSuppliedValueIsIgnored(t *testing.T) {
	m := newIsolatedMachine(t)
	config := m.newRun()
	config.Set(configuration.MACHINE_ID, 42)

	id := machineID(t, config)

	require.True(t, valid(id))
	require.Equal(t, id, readFile(t, m.shared.perUser).MachineID)
}

func TestAcceptance_AnUnstorableIDIsWarnedAboutOnce(t *testing.T) {
	m := newIsolatedMachine(t)
	m.blockEverySharedFileLocation(t)
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	config := m.newRun(WithLogger(&logger))

	for range 3 {
		require.Empty(t, machineID(t, config))
	}

	require.Equal(t, 3, strings.Count(logs.String(), "could not be stored, no stable machine id"), "each retry is logged")
	require.Equal(t, 1, strings.Count(logs.String(), `"level":"warn"`), "only the first is a warning")
}

func TestAcceptance_WriteFailuresAreLoggedWithTheirCause(t *testing.T) {
	for name, seedStudio := range map[string]bool{"generated id": false, "Snyk Studio id": true} {
		t.Run(name, func(t *testing.T) {
			m := newIsolatedMachine(t)
			m.blockEverySharedFileLocation(t)
			if seedStudio {
				seed(t, m.studio.perUser, "studio-device-id")
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

func TestAcceptance_AFailedWriteIsRetriedOnTheNextLookup(t *testing.T) {
	m := newIsolatedMachine(t)
	blocker := filepath.Dir(filepath.Dir(m.shared.perUser))
	m.blockEverySharedFileLocation(t)
	config := m.newRun()
	require.Empty(t, machineID(t, config))

	require.NoError(t, os.Remove(blocker))
	id := machineID(t, config)

	require.True(t, valid(id), "once the shared file can be written, the same process must get a stable id")
	require.Equal(t, id, readFile(t, m.shared.perUser).MachineID)
	require.Equal(t, id, machineID(t, config))
}

func TestAcceptance_TrailingWhitespaceIsTrimmedFromASuppliedID(t *testing.T) {
	m := newIsolatedMachine(t)
	t.Setenv("INTERNAL_SNYK_MACHINE_ID", "supplied-id\r\n")

	require.Equal(t, "supplied-id", machineID(t, m.newRun()))
}

func TestAcceptance_InvalidSuppliedIDIsIgnored(t *testing.T) {
	for name, raw := range map[string]string{
		"brace-wrapped guid": "{550E8400-E29B-41D4-A716-446655440000}",
		"whitespace only":    "   ",
		"leading whitespace": " supplied-id",
	} {
		t.Run(name, func(t *testing.T) {
			m := newIsolatedMachine(t)
			t.Setenv("INTERNAL_SNYK_MACHINE_ID", raw)

			id := machineID(t, m.newRun())

			require.True(t, valid(id))
			require.Equal(t, "generated", readFile(t, m.shared.perUser).IdentifierSource)
		})
	}
}

func TestAcceptance_StudioDeviceIDIsAdoptedUnchangedAndWrittenToTheSharedFile(t *testing.T) {
	m := newIsolatedMachine(t)
	seed(t, m.studio.perUser, "studio-device-id\n")

	require.Equal(t, "studio-device-id", machineID(t, m.newRun()))

	content := readFile(t, m.shared.perUser)
	require.Equal(t, "studio-device-id", content.MachineID)
	require.Equal(t, "persisted", content.IdentifierSource)
	require.Equal(t, "go-application-framework", content.Writer)
	studio, err := os.ReadFile(m.studio.perUser)
	require.NoError(t, err)
	require.Equal(t, "studio-device-id\n", string(studio), "the Studio file must be left in place")
}

func TestAcceptance_AdoptedStudioDeviceIDIsReturnedAgainAfterTheStudioFileChanges(t *testing.T) {
	m := newIsolatedMachine(t)
	seed(t, m.studio.perUser, "studio-device-id")
	require.Equal(t, "studio-device-id", machineID(t, m.newRun()))

	seed(t, m.studio.perUser, "changed-studio-device-id")
	require.Equal(t, "studio-device-id", machineID(t, m.newRun()), "once adopted, the id comes from the shared file")

	require.NoError(t, os.Remove(m.studio.perUser))
	require.Equal(t, "studio-device-id", machineID(t, m.newRun()))
}

func TestAcceptance_MachineScopeStudioDeviceIDWinsWhenScopesDisagree(t *testing.T) {
	m := newIsolatedMachine(t)
	seed(t, m.studio.machineWide, "machine-scope-id")
	seed(t, m.studio.perUser, "user-scope-id")

	require.Equal(t, "machine-scope-id", machineID(t, m.newRun()))
}

func TestAcceptance_SharedFileWinsOverStudioDeviceID(t *testing.T) {
	m := newIsolatedMachine(t)
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "from-shared-file"})
	seed(t, m.studio.machineWide, "studio-device-id")

	require.Equal(t, "from-shared-file", machineID(t, m.newRun()))
}

func TestAcceptance_StudioDeviceIDIsReturnedEvenWhenTheSharedFileCannotBeWritten(t *testing.T) {
	m := newIsolatedMachine(t)
	m.blockEverySharedFileLocation(t)
	seed(t, m.studio.perUser, "studio-device-id")

	require.Equal(t, "studio-device-id", machineID(t, m.newRun()))
}

func TestAcceptance_InvalidStudioDeviceIDIsIgnoredAndLogged(t *testing.T) {
	m := newIsolatedMachine(t)
	seed(t, m.studio.perUser, " \t{ABC-99}\x00WEIRD-interior\n\n")
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	id := machineID(t, m.newRun(WithLogger(&logger)))

	require.True(t, valid(id))
	require.Equal(t, "generated", readFile(t, m.shared.perUser).IdentifierSource)
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

	require.Equal(t, "go-application-framework", readFile(t, m.shared.perUser).Writer)
}
