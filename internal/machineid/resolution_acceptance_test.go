package machineid

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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
	serial string
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
	return Resolve(append([]ResolveOption{withPaths(m.shared, m.studio), withHardware(m.serial, "test-host")}, opts...)...)
}

// machineOf reads MACHINE_ID, requiring runtimeinfo.ErrNoMachineID exactly when no id was found.
func machineOf(t *testing.T, config configuration.Configuration) runtimeinfo.Machine {
	t.Helper()
	value, err := config.GetWithError(configuration.MACHINE_ID)
	machine, ok := value.(runtimeinfo.Machine)
	require.True(t, ok, "MACHINE_ID must hold a runtimeinfo.Machine, got %T", value)
	if machine.ID == "" {
		require.ErrorIs(t, err, runtimeinfo.ErrNoMachineID)
	} else {
		require.NoError(t, err)
	}
	return machine
}

// machineID reads the identifier of MACHINE_ID, see machineOf.
func machineID(t *testing.T, config configuration.Configuration) string {
	t.Helper()
	return machineOf(t, config).ID
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
	t.Setenv("INTERNAL_SNYK_MACHINE_ID", "not/valid")
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

func TestAcceptance_StudioIDFromDiskIsRecordedOnTheMachineWhateverSourcedTheID(t *testing.T) {
	m := newIsolatedMachine(t)
	seed(t, m.studio.perUser, "studio-device-id")
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "from-shared-file"})

	machine := machineOf(t, m.newRun())

	require.Equal(t, "from-shared-file", machine.ID)
	require.Equal(t, "studio-device-id", machine.StudioID)
}

func TestAcceptance_StudioCLIVariableFillsStudioIDWithoutSupplyingTheMachineID(t *testing.T) {
	m := newIsolatedMachine(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "studio-cli-value")

	machine := machineOf(t, m.newRun())

	require.NotEqual(t, "studio-cli-value", machine.ID)
	require.Equal(t, "studio-cli-value", machine.StudioID)
	require.Equal(t, machine.ID, readFile(t, m.shared.perUser).MachineID)
}

func TestAcceptance_InvalidStudioCLIValueFallsBackToTheStudioFile(t *testing.T) {
	m := newIsolatedMachine(t)
	seed(t, m.studio.perUser, "studio-device-id")
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "a/b")

	require.Equal(t, "studio-device-id", machineOf(t, m.newRun()).StudioID)
}

func TestAcceptance_InvalidStudioCLIValueIsLoggedOncePerResolvedLookup(t *testing.T) {
	m := newIsolatedMachine(t)
	seed(t, m.studio.perUser, "studio-device-id")
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "a/b")
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	machineOf(t, m.newRun(WithLogger(&logger)))

	failures := 0
	for _, line := range strings.Split(logs.String(), "\n") {
		if strings.Contains(line, "Snyk Studio CLI value failed validation") {
			failures++
		}
	}
	require.Equal(t, 1, failures)
}

func TestAcceptance_TrailingNewlineIsTrimmedFromStudioCLIValue(t *testing.T) {
	m := newIsolatedMachine(t)
	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "studio-cli-value\n")

	require.Equal(t, "studio-cli-value", machineOf(t, m.newRun()).StudioID)
}

func TestAcceptance_StudioIDIsTheSameWhetherTheMachineIDIsSuppliedOrResolved(t *testing.T) {
	for name, cliValue := range map[string]string{"from disk": "", "from Studio CLI variable": "studio-cli-value"} {
		t.Run(name, func(t *testing.T) {
			m := newIsolatedMachine(t)
			seed(t, m.studio.perUser, "studio-device-id")
			if cliValue != "" {
				t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", cliValue)
			}
			want := "studio-device-id"
			if cliValue != "" {
				want = cliValue
			}

			resolved := machineOf(t, m.newRun())
			t.Setenv("INTERNAL_SNYK_MACHINE_ID", "supplied-id")
			supplied := machineOf(t, m.newRun())

			require.Equal(t, want, resolved.StudioID)
			require.Equal(t, want, supplied.StudioID)
		})
	}
}

func TestAcceptance_StudioCLIVariableSetAfterTheFirstLookupIsUsedOnTheResolvedPath(t *testing.T) {
	m := newIsolatedMachine(t)
	seed(t, m.studio.perUser, "studio-device-id")
	config := m.newRun()
	require.Equal(t, "studio-device-id", machineOf(t, config).StudioID)

	t.Setenv("INTERNAL_SNYK_CLIENT_MACHINE_ID", "studio-cli-value")

	require.Equal(t, "studio-cli-value", machineOf(t, config).StudioID)
}

func TestAcceptance_UnreadableStudioFileIsLoggedOnceForASuppliedMachine(t *testing.T) {
	m := newIsolatedMachine(t)
	t.Setenv("INTERNAL_SNYK_MACHINE_ID", "supplied-id")
	seed(t, m.studio.perUser, "studio-device-id")
	restore := makeUnreadable(t, m.studio.perUser)
	defer restore()
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	config := m.newRun(WithLogger(&logger))

	for range 3 {
		machineOf(t, config)
	}

	require.Equal(t, 1, strings.Count(logs.String(), "could not be read for the machine description"))
}

func TestAcceptance_StudioIDOfASuppliedMachineIsReadOnce(t *testing.T) {
	m := newIsolatedMachine(t)
	seed(t, m.studio.perUser, "studio-device-id")
	t.Setenv("INTERNAL_SNYK_MACHINE_ID", "supplied-id")
	config := m.newRun()
	first := machineOf(t, config)

	seed(t, m.studio.perUser, "changed-studio-device-id")

	require.Equal(t, "studio-device-id", first.StudioID)
	require.Equal(t, first.StudioID, machineOf(t, config).StudioID)
}

func TestAcceptance_HardwareSerialWinsOverAnIDInTheSharedFile(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	writeSharedFileAs(t, m.shared.machineWide, map[string]any{"machine_id": "from-shared-file"})

	machine := machineOf(t, m.newRun())

	require.Equal(t, "C02Q7KHTGFWF", machine.ID)
	require.Equal(t, "C02Q7KHTGFWF", machine.SerialNumber)
	require.Equal(t, "C02Q7KHTGFWF", readFile(t, m.shared.machineWide).MachineID)
}

func TestAcceptance_HardwareSerialReplacesADifferentIDInTheMachineWideFile(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	writeSharedFileAs(t, m.shared.machineWide, map[string]any{"machine_id": "from-shared-file", "identifier_source": "generated"})

	machineOf(t, m.newRun())

	content := readFile(t, m.shared.machineWide)
	require.Equal(t, "C02Q7KHTGFWF", content.MachineID)
	require.Equal(t, "serial", content.IdentifierSource)
}

func TestAcceptance_HardwareSerialReplacementKeepsTheFirstSeenTimeOfTheReplacedFile(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	const firstSeen = "2020-01-02T03:04:05Z"
	writeSharedFileAs(t, m.shared.machineWide, map[string]any{"machine_id": "from-shared-file", "identifier_source": "generated", "first_seen_at": firstSeen})

	machineOf(t, m.newRun())

	content := readFile(t, m.shared.machineWide)
	require.Equal(t, "C02Q7KHTGFWF", content.MachineID)
	require.Equal(t, firstSeen, content.FirstSeenAt)
}

func TestAcceptance_HardwareSerialConvergesOnAFileFirstWrittenByAnotherSource(t *testing.T) {
	m := newIsolatedMachine(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(m.shared.machineWide), 0o755))
	generated := machineID(t, m.newRun())
	require.NotEqual(t, "C02Q7KHTGFWF", generated)

	m.serial = "C02Q7KHTGFWF"
	machine := machineOf(t, m.newRun())

	require.Equal(t, "C02Q7KHTGFWF", machine.ID)
	content := readFile(t, m.shared.machineWide)
	require.Equal(t, "C02Q7KHTGFWF", content.MachineID)
	require.Equal(t, "serial", content.IdentifierSource)
}

func TestAcceptance_HardwareSerialReplacesAPerUserIDWhenNoMachineWideFileExists(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	seed(t, m.shared.perUser, `{"machine_id":"from-shared-file","identifier_source":"generated"}`)

	machine, err := runtimeInfoOf(m.newRun()).GetMachineID()

	require.NoError(t, err)
	require.Equal(t, "C02Q7KHTGFWF", machine.ID)
	content := readFile(t, m.shared.perUser)
	require.Equal(t, "C02Q7KHTGFWF", content.MachineID)
	require.Equal(t, "serial", content.IdentifierSource)
	require.NoFileExists(t, m.shared.machineWide)
}

func TestAcceptance_HardwareSerialReplacesAPerUserIDWhenTheMachineWideFileAlreadyHoldsTheSerial(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	seed(t, m.shared.machineWide, `{"machine_id":"C02Q7KHTGFWF","identifier_source":"serial"}`)
	seed(t, m.shared.perUser, `{"machine_id":"from-shared-file","identifier_source":"generated"}`)

	machine, err := runtimeInfoOf(m.newRun()).GetMachineID()

	require.NoError(t, err)
	require.Equal(t, "C02Q7KHTGFWF", machine.ID)
	require.Equal(t, "C02Q7KHTGFWF", readFile(t, m.shared.perUser).MachineID)
}

func TestAcceptance_HardwareSerialDoesNotReplaceASharedFileItCannotRead(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	seed(t, m.shared.perUser, `{"machine_id":"from-shared-file"}`)
	restore := makeUnreadable(t, m.shared.perUser)

	machine, err := runtimeInfoOf(m.newRun()).GetMachineID()

	restore()
	require.ErrorContains(t, err, "unreadable")
	require.Equal(t, "C02Q7KHTGFWF", machine.ID)
	require.Equal(t, "from-shared-file", readFile(t, m.shared.perUser).MachineID)
}

func TestAcceptance_HardwareSerialLeavesASharedFileWrittenByANewerSchemaUnchanged(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	newer := `{"machine_id":"from-newer-schema","schema_version":2}`
	seed(t, m.shared.machineWide, newer)
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	machine, err := runtimeInfoOf(m.newRun(WithLogger(&logger))).GetMachineID()

	require.NoError(t, err)
	require.Equal(t, "C02Q7KHTGFWF", machine.ID)
	raw, readErr := os.ReadFile(m.shared.machineWide)
	require.NoError(t, readErr)
	require.Equal(t, newer, string(raw))
	line := logLineContaining(t, logs.String(), "newer or unknown schema")
	require.Contains(t, line, `"level":"warn"`)
}

func TestAcceptance_HardwareSerialLeavesANewerSchemaMachineWideFileUnchangedWhenItsDirectoryIsReadOnly(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	newer := `{"machine_id":"from-newer-schema","schema_version":2}`
	seed(t, m.shared.machineWide, newer)
	makeUnwritable(t, filepath.Dir(m.shared.machineWide))
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	machine, err := runtimeInfoOf(m.newRun(WithLogger(&logger))).GetMachineID()

	require.NoError(t, err)
	require.Equal(t, "C02Q7KHTGFWF", machine.ID)
	raw, readErr := os.ReadFile(m.shared.machineWide)
	require.NoError(t, readErr)
	require.Equal(t, newer, string(raw))
	require.NoFileExists(t, m.shared.perUser)
	line := logLineContaining(t, logs.String(), "newer or unknown schema")
	require.Contains(t, line, `"level":"warn"`)
	require.NotContains(t, logs.String(), "could not be replaced")
}

func TestAcceptance_HardwareSerialLeavesANonIntegerSchemaSharedFileUnchanged(t *testing.T) {
	for name, version := range map[string]string{"string": `"1"`, "fractional": "1.5", "whole float": "1.0"} {
		t.Run(name, func(t *testing.T) {
			m := newIsolatedMachine(t)
			m.serial = "C02Q7KHTGFWF"
			original := `{"machine_id":"from-shared-file","schema_version":` + version + `}`
			seed(t, m.shared.machineWide, original)

			machine, err := runtimeInfoOf(m.newRun()).GetMachineID()

			require.NoError(t, err)
			require.Equal(t, "C02Q7KHTGFWF", machine.ID)
			raw, readErr := os.ReadFile(m.shared.machineWide)
			require.NoError(t, readErr)
			require.Equal(t, original, string(raw))
		})
	}
}

func TestAcceptance_HardwareSerialLeavesAnInvalidIDSharedFileWithANewerSchemaUnchanged(t *testing.T) {
	for name, original := range map[string]string{
		"overlong id": `{"machine_id":"` + strings.Repeat("a", 129) + `","schema_version":2}`,
		"empty id":    `{"machine_id":"","schema_version":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			m := newIsolatedMachine(t)
			m.serial = "C02Q7KHTGFWF"
			seed(t, m.shared.machineWide, original)
			var logs bytes.Buffer
			logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

			machine, err := runtimeInfoOf(m.newRun(WithLogger(&logger))).GetMachineID()

			require.NoError(t, err)
			require.Equal(t, "C02Q7KHTGFWF", machine.ID)
			raw, readErr := os.ReadFile(m.shared.machineWide)
			require.NoError(t, readErr)
			require.Equal(t, original, string(raw))
			require.NoFileExists(t, m.shared.perUser)
			require.Contains(t, logLineContaining(t, logs.String(), "newer or unknown schema"), `"level":"warn"`)
			require.NotContains(t, logs.String(), "could not be stored")
		})
	}
}

func TestAcceptance_HardwareSerialReplacesAnInvalidIDSharedFileWithoutANewerSchema(t *testing.T) {
	for name, original := range map[string]string{
		"missing schema": `{"machine_id":""}`,
		"not json":       `not json at all`,
	} {
		t.Run(name, func(t *testing.T) {
			m := newIsolatedMachine(t)
			m.serial = "C02Q7KHTGFWF"
			seed(t, m.shared.machineWide, original)

			machine, err := runtimeInfoOf(m.newRun()).GetMachineID()

			require.NoError(t, err)
			require.Equal(t, "C02Q7KHTGFWF", machine.ID)
			require.Equal(t, "C02Q7KHTGFWF", readFile(t, m.shared.machineWide).MachineID)
		})
	}
}

func TestAcceptance_HardwareSerialDoesNotWarnOrWriteWhenAReadOnlyMachineWideFileAlreadyHoldsIt(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	original := `{"machine_id":"C02Q7KHTGFWF","identifier_source":"serial"}`
	seed(t, m.shared.machineWide, original)
	makeUnwritable(t, filepath.Dir(m.shared.machineWide))
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	machine, err := runtimeInfoOf(m.newRun(WithLogger(&logger))).GetMachineID()

	require.NoError(t, err)
	require.Equal(t, "C02Q7KHTGFWF", machine.ID)
	raw, readErr := os.ReadFile(m.shared.machineWide)
	require.NoError(t, readErr)
	require.Equal(t, original, string(raw))
	require.NoFileExists(t, m.shared.perUser)
	require.NotContains(t, logs.String(), `"level":"warn"`)
}

func TestAcceptance_HardwareSerialDoesNotShadowANewerSchemaMachineWideFileWithAPerUserID(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	newer := `{"machine_id":"from-newer-schema","schema_version":2}`
	seed(t, m.shared.machineWide, newer)

	machine, err := runtimeInfoOf(m.newRun()).GetMachineID()

	require.NoError(t, err)
	require.Equal(t, "C02Q7KHTGFWF", machine.ID)
	raw, readErr := os.ReadFile(m.shared.machineWide)
	require.NoError(t, readErr)
	require.Equal(t, newer, string(raw))
	require.NoFileExists(t, m.shared.perUser)
}

func TestAcceptance_HardwareSerialLeavesAReadOnlyMachineWideIDUnchangedWithoutAPerUserFileOrWarning(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	original := `{"machine_id":"from-shared-file"}`
	seed(t, m.shared.machineWide, original)
	makeUnwritable(t, filepath.Dir(m.shared.machineWide))
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	machine, err := runtimeInfoOf(m.newRun(WithLogger(&logger))).GetMachineID()

	require.NoError(t, err)
	require.Equal(t, "C02Q7KHTGFWF", machine.ID)
	raw, readErr := os.ReadFile(m.shared.machineWide)
	require.NoError(t, readErr)
	require.Equal(t, original, string(raw))
	require.NoFileExists(t, m.shared.perUser)
	require.NotContains(t, logs.String(), `"level":"warn"`)
	line := logLineContaining(t, logs.String(), "shared file holds a different machine id")
	require.Contains(t, line, `"level":"debug"`)
}

func TestAcceptance_HardwareSerialDoesNotWarnOnRepeatedRunsWithAReadOnlyMachineWideID(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	seed(t, m.shared.machineWide, `{"machine_id":"from-shared-file"}`)
	makeUnwritable(t, filepath.Dir(m.shared.machineWide))
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	for range 3 {
		require.Equal(t, "C02Q7KHTGFWF", machineID(t, m.newRun(WithLogger(&logger))))
	}

	require.NotContains(t, logs.String(), `"level":"warn"`)
	require.NotContains(t, logs.String(), `"level":"error"`)
	require.NoFileExists(t, m.shared.perUser)
}

func TestAcceptance_HardwareSerialLeavesAMachineWideIDUnchangedWhenItsDirectoryIsReadOnly(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	seed(t, m.shared.machineWide, `{"machine_id":"from-shared-file"}`)
	makeUnwritable(t, filepath.Dir(m.shared.machineWide))
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	machine, err := runtimeInfoOf(m.newRun(WithLogger(&logger))).GetMachineID()

	require.NoError(t, err)
	require.Equal(t, "C02Q7KHTGFWF", machine.ID)
	require.Equal(t, "from-shared-file", readFile(t, m.shared.machineWide).MachineID)
	require.NoFileExists(t, m.shared.perUser)
	require.NotContains(t, logs.String(), `"level":"warn"`)
	require.Contains(t, logLineContaining(t, logs.String(), "could not be replaced"), `"level":"debug"`)
}

func TestAcceptance_HardwareSerialLeavesAMachineWideIDUnchangedAndWarnsWhenItsLockIsHeld(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	seed(t, m.shared.machineWide, `{"machine_id":"from-shared-file"}`)
	holdLock(t, m.shared.machineWide)
	shortenLockTimeout(t)
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	machine, err := runtimeInfoOf(m.newRun(WithLogger(&logger))).GetMachineID()

	require.NoError(t, err)
	require.Equal(t, "C02Q7KHTGFWF", machine.ID)
	require.Equal(t, "from-shared-file", readFile(t, m.shared.machineWide).MachineID)
	line := logLineContaining(t, logs.String(), "could not be replaced")
	require.Contains(t, line, `"level":"warn"`)
	require.Contains(t, line, jsonEscaped(t, m.shared.machineWide))
}

func TestAcceptance_HardwareSerialCreatesTheMachineWideFileWhenOnlyAPerUserIDDiffers(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	seed(t, m.shared.perUser, `{"machine_id":"from-shared-file","identifier_source":"generated"}`)
	require.NoError(t, os.MkdirAll(filepath.Dir(m.shared.machineWide), 0o755))

	machine, err := runtimeInfoOf(m.newRun()).GetMachineID()

	require.NoError(t, err)
	require.Equal(t, "C02Q7KHTGFWF", machine.ID)
	require.Equal(t, "C02Q7KHTGFWF", readFile(t, m.shared.machineWide).MachineID)
	require.Equal(t, "C02Q7KHTGFWF", readFile(t, m.shared.perUser).MachineID)
}

func TestAcceptance_HardwareSerialIsStoredPerUserWhenNoSharedFileExistsAndMachineWideIsReadOnly(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	require.NoError(t, os.MkdirAll(filepath.Dir(m.shared.machineWide), 0o755))
	makeUnwritable(t, filepath.Dir(m.shared.machineWide))

	machine, err := runtimeInfoOf(m.newRun()).GetMachineID()

	require.NoError(t, err)
	require.Equal(t, "C02Q7KHTGFWF", machine.ID)
	require.NoFileExists(t, m.shared.machineWide)
	require.Equal(t, "C02Q7KHTGFWF", readFile(t, m.shared.perUser).MachineID)
}

func TestAcceptance_HardwareSerialReplacesAMachineWideIDWithoutWarning(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	writeSharedFileAs(t, m.shared.machineWide, map[string]any{"machine_id": "from-shared-file", "identifier_source": "generated"})
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	machineOf(t, m.newRun(WithLogger(&logger)))

	require.Equal(t, "C02Q7KHTGFWF", readFile(t, m.shared.machineWide).MachineID)
	require.NotContains(t, logs.String(), `"level":"warn"`)
}

func TestAcceptance_ConcurrentResolversAgreeOnTheSerialWhenAMachineWideIDIsReplaced(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	writeSharedFileAs(t, m.shared.machineWide, map[string]any{"machine_id": "from-shared-file"})
	const resolvers = 8
	ids := make([]string, resolvers)
	errs := make([]error, resolvers)
	var wg sync.WaitGroup
	for i := range resolvers {
		wg.Go(func() {
			machine, err := runtimeInfoOf(m.newRun()).GetMachineID()
			ids[i], errs[i] = machine.ID, err
		})
	}
	wg.Wait()

	for i := range resolvers {
		require.NoError(t, errs[i])
		require.Equal(t, "C02Q7KHTGFWF", ids[i])
	}
	require.Equal(t, "C02Q7KHTGFWF", readFile(t, m.shared.machineWide).MachineID)
}

func TestAcceptance_HardwareSerialLeavesAFileAlreadyHoldingTheSerialUntouched(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "C02Q7KHTGFWF", "identifier_source": "serial"})
	before, err := os.Stat(m.shared.perUser)
	require.NoError(t, err)
	contentBefore, err := os.ReadFile(m.shared.perUser)
	require.NoError(t, err)
	past := before.ModTime().Add(-time.Hour)
	require.NoError(t, os.Chtimes(m.shared.perUser, past, past))

	machineOf(t, m.newRun())

	after, err := os.Stat(m.shared.perUser)
	require.NoError(t, err)
	contentAfter, err := os.ReadFile(m.shared.perUser)
	require.NoError(t, err)
	require.Equal(t, string(contentBefore), string(contentAfter))
	require.True(t, past.Equal(after.ModTime()), "mtime changed from %v to %v", past, after.ModTime())
}

func TestAcceptance_HardwareSerialIsStoredInAnEmptyOrMissingSharedFile(t *testing.T) {
	for name, content := range map[string]*string{"missing": nil, "empty": new(string)} {
		t.Run(name, func(t *testing.T) {
			m := newIsolatedMachine(t)
			m.serial = "C02Q7KHTGFWF"
			if content != nil {
				seed(t, m.shared.perUser, *content)
			}

			id := machineID(t, m.newRun())

			require.Equal(t, "C02Q7KHTGFWF", id)
			stored := readFile(t, m.shared.perUser)
			require.Equal(t, "C02Q7KHTGFWF", stored.MachineID)
			require.Equal(t, "serial", stored.IdentifierSource)
		})
	}
}

func TestAcceptance_HardwareSerialWithInternalSpacesIsUsedAndStored(t *testing.T) {
	m := newIsolatedMachine(t)
	serial := "VMware-56 4d 12 34 ab cd ef 01-23 45 67 89 ab cd ef 01"
	m.serial = serial

	machine, err := runtimeInfoOf(m.newRun()).GetMachineID()
	require.NoError(t, err)

	require.Equal(t, serial, machine.ID)
	stored := readFile(t, m.shared.perUser)
	require.Equal(t, serial, stored.MachineID)
	require.Equal(t, "serial", stored.IdentifierSource)
	require.Equal(t, serial, machineID(t, m.newRun()))
}

func TestAcceptance_HardwareSerialIsReturnedWithoutAnErrorWhenAnExistingIDCannotBeReplaced(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	seed(t, m.shared.machineWide, `{"machine_id":"from-shared-file"}`)
	require.NoError(t, os.MkdirAll(filepath.Dir(m.shared.perUser), 0o755))
	makeUnwritable(t, filepath.Dir(m.shared.machineWide))
	makeUnwritable(t, filepath.Dir(m.shared.perUser))

	machine, err := runtimeInfoOf(m.newRun()).GetMachineID()

	require.NoError(t, err)
	require.Equal(t, "C02Q7KHTGFWF", machine.ID)
	require.Equal(t, "from-shared-file", readFile(t, m.shared.machineWide).MachineID)
	require.NoFileExists(t, m.shared.perUser)
}

func TestAcceptance_HardwareSerialOutsideTheAllowedCharactersIsNotUsedAsTheID(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02/Q7KHTGFWF"

	machine := machineOf(t, m.newRun())

	require.NotEqual(t, "C02/Q7KHTGFWF", machine.ID)
	require.True(t, valid(machine.ID))
	require.Equal(t, machine.ID, readFile(t, m.shared.perUser).MachineID)
}

func TestAcceptance_HardwareSerialReadErrorIsLoggedAtDebugAndNotReturned(t *testing.T) {
	m := newIsolatedMachine(t)
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	failSerial := func(o *resolveOptions) {
		o.serialNumber = func() (string, error) { return "", errors.New("serial query failed") }
	}

	machine, err := runtimeInfoOf(m.newRun(WithLogger(&logger), failSerial)).GetMachineID()

	require.NoError(t, err)
	require.True(t, valid(machine.ID))
	line := logLineContaining(t, logs.String(), "serial")
	require.Contains(t, line, `"level":"debug"`)
	require.Contains(t, line, "serial query failed")
}

func TestAcceptance_APermanentlyFailingHardwareSerialProbeRunsOnceForAllLookups(t *testing.T) {
	for name, supplied := range map[string]bool{"resolved id": false, "supplied id": true} {
		t.Run(name, func(t *testing.T) {
			m := newIsolatedMachine(t)
			if supplied {
				t.Setenv("INTERNAL_SNYK_MACHINE_ID", "supplied-id")
			}
			probes := 0
			failingSerial := func(o *resolveOptions) {
				o.serialNumber = func() (string, error) {
					probes++
					return "", errors.New("serial query failed")
				}
			}
			config := m.newRun(failingSerial)

			for range 3 {
				machineOf(t, config)
			}

			require.Equal(t, 1, probes)
		})
	}
}

func TestAcceptance_HardwareSerialIsReadOnceForASuppliedMachine(t *testing.T) {
	m := newIsolatedMachine(t)
	t.Setenv("INTERNAL_SNYK_MACHINE_ID", "supplied-id")
	reads := 0
	countSerial := func(o *resolveOptions) {
		o.serialNumber = func() (string, error) {
			reads++
			return "C02Q7KHTGFWF", nil
		}
	}
	config := m.newRun(countSerial)

	machineOf(t, config)
	machineOf(t, config)

	require.Equal(t, 1, reads)
}

func TestAcceptance_SuppliedIDStillReturnsHostnameAndSerial(t *testing.T) {
	m := newIsolatedMachine(t)
	t.Setenv("INTERNAL_SNYK_MACHINE_ID", "supplied-id")
	serialReads := 0
	hostnameReads := 0
	countSerial := func(o *resolveOptions) {
		o.serialNumber = func() (string, error) {
			serialReads++
			return "C02Q7KHTGFWF", nil
		}
	}
	countHostname := func(o *resolveOptions) {
		o.hostname = func() (string, error) {
			hostnameReads++
			return "host.example", nil
		}
	}
	config := m.newRun(countSerial, countHostname)

	machine, err := runtimeInfoOf(config).GetMachineID()

	require.NoError(t, err)
	require.Equal(t, runtimeinfo.Machine{ID: "supplied-id", Hostname: "host.example", SerialNumber: "C02Q7KHTGFWF"}, machine)
	require.Equal(t, 1, serialReads)
	require.Equal(t, 1, hostnameReads)
}

func TestAcceptance_InvalidHardwareSerialReasonIsLoggedAtDebug(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02/Q7KHTGFWF"
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	machineID(t, m.newRun(WithLogger(&logger)))

	line := logLineContaining(t, logs.String(), "contains characters outside the allowed set")
	require.Contains(t, line, `"level":"debug"`)
}

func TestAcceptance_HardwareSerialIsReturnedWithoutAnErrorWhenTheSharedFileCannotBeWritten(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	m.blockEverySharedFileLocation(t)

	machine, err := runtimeInfoOf(m.newRun()).GetMachineID()

	require.NoError(t, err)
	require.Equal(t, "C02Q7KHTGFWF", machine.ID)
}

func TestAcceptance_HardwareSerialStoreFailuresAreLoggedPerLocationWithTheirOwnPath(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	m.blockEverySharedFileLocation(t)
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	machine, err := runtimeInfoOf(m.newRun(WithLogger(&logger))).GetMachineID()

	require.NoError(t, err)
	require.Equal(t, "C02Q7KHTGFWF", machine.ID)
	perUser := logLineContaining(t, logs.String(), `"path":"`+jsonEscaped(t, m.shared.perUser)+`","message":"machine id: serial number could not be stored`)
	require.Contains(t, perUser, `"level":"warn"`)
	machineWide := logLineContaining(t, logs.String(), `"path":"`+jsonEscaped(t, m.shared.machineWide)+`","message":"machine id: serial number could not be stored`)
	require.Contains(t, machineWide, `"level":"debug"`)
}

func TestAcceptance_HardwareSerialReplaceLogsAMissingMachineWideDirectoryAtDebug(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	seed(t, m.shared.perUser, `{"machine_id":"from-shared-file","identifier_source":"generated"}`)
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	machineOf(t, m.newRun(WithLogger(&logger)))

	require.Equal(t, "C02Q7KHTGFWF", readFile(t, m.shared.perUser).MachineID)
	require.NotContains(t, logs.String(), `"level":"warn"`)
	line := logLineContaining(t, logs.String(), "could not be replaced")
	require.Contains(t, line, `"level":"debug"`)
	require.Contains(t, line, jsonEscaped(t, m.shared.machineWide))
}

func TestAcceptance_HardwareSerialReplacesAPerUserIDSilentlyWhenThereIsNoMachineWidePath(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	m.shared.machineWide = ""
	seed(t, m.shared.perUser, `{"machine_id":"from-shared-file","identifier_source":"generated"}`)
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	machineOf(t, m.newRun(WithLogger(&logger)))

	require.Equal(t, "C02Q7KHTGFWF", readFile(t, m.shared.perUser).MachineID)
	require.NotContains(t, logs.String(), `"level":"warn"`)
}

func TestAcceptance_HardwareSerialDoesNotWarnAboutANewerSchemaPerUserFileWhenMachineWideHoldsTheSerial(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	seed(t, m.shared.machineWide, `{"machine_id":"C02Q7KHTGFWF","identifier_source":"serial"}`)
	newer := `{"machine_id":"from-newer-schema","schema_version":2}`
	seed(t, m.shared.perUser, newer)
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	for range 2 {
		require.Equal(t, "C02Q7KHTGFWF", machineID(t, m.newRun(WithLogger(&logger))))
	}

	require.NotContains(t, logs.String(), `"level":"warn"`)
	raw, err := os.ReadFile(m.shared.perUser)
	require.NoError(t, err)
	require.Equal(t, newer, string(raw))
}

func TestAcceptance_HardwareSerialWarnsAboutANewerSchemaPerUserFileThatResolutionRead(t *testing.T) {
	m := newIsolatedMachine(t)
	m.serial = "C02Q7KHTGFWF"
	newer := `{"machine_id":"from-newer-schema","schema_version":2}`
	seed(t, m.shared.perUser, newer)
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)

	require.Equal(t, "C02Q7KHTGFWF", machineID(t, m.newRun(WithLogger(&logger))))

	line := logLineContaining(t, logs.String(), "newer or unknown schema")
	require.Contains(t, line, `"level":"warn"`)
	require.Contains(t, line, jsonEscaped(t, m.shared.perUser))
	raw, err := os.ReadFile(m.shared.perUser)
	require.NoError(t, err)
	require.Equal(t, newer, string(raw))
}

func TestAcceptance_DirectMachineValueSetBeforeFirstReadIsReturned(t *testing.T) {
	m := newIsolatedMachine(t)
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "from-shared-file"})
	config := m.newRun()
	config.Set(configuration.MACHINE_ID, runtimeinfo.Machine{
		ID:           "supplied-id",
		Hostname:     "box",
		SerialNumber: "SN1",
		StudioID:     "studio-1",
	})

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	machine, ok := value.(runtimeinfo.Machine)
	require.True(t, ok)
	require.Equal(t, "supplied-id", machine.ID)
	require.Equal(t, "box", machine.Hostname)
	require.Equal(t, "SN1", machine.SerialNumber)
	require.Equal(t, "studio-1", machine.StudioID)
}

func TestAcceptance_PointerToMachineValueSetBeforeFirstReadIsReturned(t *testing.T) {
	m := newIsolatedMachine(t)
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "from-shared-file"})
	config := m.newRun()
	machinePtr := &runtimeinfo.Machine{
		ID:           "supplied-id",
		Hostname:     "box",
		SerialNumber: "SN1",
		StudioID:     "studio-1",
	}
	config.Set(configuration.MACHINE_ID, machinePtr)

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	machine, ok := value.(runtimeinfo.Machine)
	require.True(t, ok)
	require.Equal(t, "supplied-id", machine.ID)
	require.Equal(t, "box", machine.Hostname)
	require.Equal(t, "SN1", machine.SerialNumber)
	require.Equal(t, "studio-1", machine.StudioID)
}

func TestAcceptance_NilPointerToMachineIsNotSupplied(t *testing.T) {
	m := newIsolatedMachine(t)
	seededID := "from-shared-file"
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": seededID})
	config := m.newRun()
	var machinePtr *runtimeinfo.Machine
	config.Set(configuration.MACHINE_ID, machinePtr)

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	machine, ok := value.(runtimeinfo.Machine)
	require.True(t, ok)
	require.Equal(t, seededID, machine.ID)
}

func TestAcceptance_MachineWithEmptyIDIsNotSupplied(t *testing.T) {
	m := newIsolatedMachine(t)
	seededID := "from-shared-file"
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": seededID})
	config := m.newRun()
	config.Set(configuration.MACHINE_ID, runtimeinfo.Machine{
		Hostname: "box",
	})

	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	machine, ok := value.(runtimeinfo.Machine)
	require.True(t, ok)
	require.Equal(t, seededID, machine.ID)
}

func TestAcceptance_JSONEnvironmentVariableWithMachineObjectWinsOverSeededFile(t *testing.T) {
	m := newIsolatedMachine(t)
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "from-shared-file"})
	t.Setenv("INTERNAL_SNYK_MACHINE_ID", `{"ID":"supplied-id","Hostname":"box","SerialNumber":"SN1","StudioID":"studio-1"}
`)

	config := m.newRun()
	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	machine, ok := value.(runtimeinfo.Machine)
	require.True(t, ok)
	require.Equal(t, "supplied-id", machine.ID)
	require.Equal(t, "box", machine.Hostname)
	require.Equal(t, "SN1", machine.SerialNumber)
	require.Equal(t, "studio-1", machine.StudioID)
}

func TestAcceptance_JSONEnvironmentVariableWithInvalidIDIsIgnored(t *testing.T) {
	m := newIsolatedMachine(t)
	t.Setenv("INTERNAL_SNYK_MACHINE_ID", `{"ID":"not/valid","Hostname":"box"}`)

	id := machineID(t, m.newRun())

	require.True(t, valid(id), "invalid supplied ID must be ignored, so a generated id is used")
	require.Equal(t, "generated", readFile(t, m.shared.perUser).IdentifierSource)
}

func TestAcceptance_EnvironmentVariableNullWinsOverSeededFile(t *testing.T) {
	m := newIsolatedMachine(t)
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "from-shared-file"})
	t.Setenv("INTERNAL_SNYK_MACHINE_ID", "null")

	config := m.newRun()
	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	machine, ok := value.(runtimeinfo.Machine)
	require.True(t, ok)
	require.Equal(t, "null", machine.ID)
}

func TestAcceptance_JSONObjectWithLeadingWhitespaceWinsOverTheSeededFile(t *testing.T) {
	m := newIsolatedMachine(t)
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "from-shared-file"})
	t.Setenv("INTERNAL_SNYK_MACHINE_ID", "\n{\"ID\":\"supplied-id\",\"Hostname\":\"box\"}")

	config := m.newRun()
	value, err := config.GetWithError(configuration.MACHINE_ID)
	require.NoError(t, err)
	machine, ok := value.(runtimeinfo.Machine)
	require.True(t, ok)
	require.Equal(t, "supplied-id", machine.ID)
	require.Equal(t, "box", machine.Hostname)
}

func TestAcceptance_JSONObjectWithoutAnIDUsesTheSeededFile(t *testing.T) {
	m := newIsolatedMachine(t)
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "from-shared-file"})
	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	t.Setenv("INTERNAL_SNYK_MACHINE_ID", `{"Hostname":"box"}`)

	config := m.newRun(WithLogger(&logger))
	id := machineID(t, config)

	require.Equal(t, "from-shared-file", id)
	require.Contains(t, logs.String(), "no usable id")
}
