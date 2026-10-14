package machineid

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/runtimeinfo"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func runtimeInfoOf(config configuration.Configuration) runtimeinfo.RuntimeInfo {
	engine := workflow.NewWorkFlowEngine(config)
	engine.SetRuntimeInfo(runtimeinfo.New())
	return engine.GetRuntimeInfo()
}

func catalogErrorsIn(err error) []snyk_errors.Error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var found []snyk_errors.Error
		for _, e := range joined.Unwrap() {
			found = append(found, catalogErrorsIn(e)...)
		}
		return found
	}
	var catalogErr snyk_errors.Error
	if errors.As(err, &catalogErr) {
		return []snyk_errors.Error{catalogErr}
	}
	return nil
}

func requireUnreadableFileReported(t *testing.T, err error, path string) {
	t.Helper()
	for _, e := range catalogErrorsIn(err) {
		if e.ErrorCode == "SNYK-CLI-0030" && e.Meta["path"] == path {
			require.Contains(t, e.Detail, path)
			require.NotNil(t, e.Cause, "the operating system error must be attached")
			return
		}
	}
	t.Fatalf("no SNYK-CLI-0030 error for %s in %v", path, err)
}

func TestAcceptance_UnreadableSharedFileIsReportedAlongsideTheIDFoundAfterIt(t *testing.T) {
	m := newIsolatedMachine(t)
	writeSharedFileAs(t, m.shared.machineWide, map[string]any{"machine_id": "machine-wide-id"})
	makeUnreadable(t, m.shared.machineWide)
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "per-user-id"})

	machine, err := runtimeInfoOf(m.newRun()).GetMachineID()
	id := machine.ID

	require.Equal(t, "per-user-id", id)
	requireUnreadableFileReported(t, err, m.shared.machineWide)
}

func TestAcceptance_UnreadableSharedFileWithNothingStorableIsReportedWithTheWriteFailure(t *testing.T) {
	m := newIsolatedMachine(t)
	writeSharedFileAs(t, m.shared.machineWide, map[string]any{"machine_id": "machine-wide-id"})
	makeUnreadable(t, m.shared.machineWide)
	m.blockEverySharedFileLocation(t)

	machine, err := runtimeInfoOf(m.newRun()).GetMachineID()
	id := machine.ID

	require.Empty(t, id)
	require.ErrorIs(t, err, runtimeinfo.ErrNoMachineID)
	requireUnreadableFileReported(t, err, m.shared.machineWide)
	requireNotPersistedReported(t, err, filepath.Dir(filepath.Dir(m.shared.perUser)))
}

func requireNotPersistedReported(t *testing.T, err error, blockedPath string) {
	t.Helper()
	for _, e := range catalogErrorsIn(err) {
		if e.ErrorCode == "SNYK-CLI-0031" {
			require.Contains(t, e.Detail, blockedPath, "the write failure must be in the detail")
			require.Error(t, e.Cause)
			return
		}
	}
	t.Fatalf("no SNYK-CLI-0031 error in %v", err)
}

func TestAcceptance_RepeatedLookupsReportTheSameIDAndUnreadableFile(t *testing.T) {
	for name, opts := range map[string][]configuration.Opts{
		"caching off": nil,
		"caching on":  {configuration.WithCachingEnabled(configuration.NoCacheExpiration)},
	} {
		t.Run(name, func(t *testing.T) {
			m := newIsolatedMachine(t)
			writeSharedFileAs(t, m.shared.machineWide, map[string]any{"machine_id": "machine-wide-id"})
			restore := makeUnreadable(t, m.shared.machineWide)
			writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "per-user-id"})
			config := configuration.NewWithOpts(append([]configuration.Opts{configuration.WithFiles("snyk"), configuration.WithAutomaticEnv()}, opts...)...)
			config.AddDefaultValue(configuration.MACHINE_ID, m.resolve())
			ri := runtimeInfoOf(config)
			firstMachine, firstErr := ri.GetMachineID()

			restore()
			machine, err := ri.GetMachineID()

			require.Equal(t, firstMachine, machine)
			require.Equal(t, firstErr, err, "the id is kept for the life of the engine, and so is the error it was found with")
		})
	}
}

func TestAcceptance_SuppliedIDIsReturnedWithoutReportingUnreadableFiles(t *testing.T) {
	m := newIsolatedMachine(t)
	writeSharedFileAs(t, m.shared.machineWide, map[string]any{"machine_id": "machine-wide-id"})
	makeUnreadable(t, m.shared.machineWide)
	t.Setenv("INTERNAL_SNYK_MACHINE_ID", "supplied-id")

	machine, err := runtimeInfoOf(m.newRun()).GetMachineID()
	id := machine.ID

	require.NoError(t, err)
	require.Equal(t, "supplied-id", id)
}

func TestAcceptance_UnreadableStudioDeviceIDFilesAreReportedAlongsideTheGeneratedID(t *testing.T) {
	m := newIsolatedMachine(t)
	for _, p := range []string{m.studio.machineWide, m.studio.perUser} {
		seed(t, p, "studio-device-id")
		makeUnreadable(t, p)
	}

	machine, err := runtimeInfoOf(m.newRun()).GetMachineID()
	id := machine.ID

	require.Equal(t, readFile(t, m.shared.perUser).MachineID, id)
	requireUnreadableFileReported(t, err, m.studio.machineWide)
	requireUnreadableFileReported(t, err, m.studio.perUser)
}

func TestAcceptance_ADirectoryAtTheSharedFilePathIsReportedAsUnreadable(t *testing.T) {
	m := newIsolatedMachine(t)
	require.NoError(t, os.MkdirAll(m.shared.machineWide, 0o755))
	writeSharedFileAs(t, m.shared.perUser, map[string]any{"machine_id": "per-user-id"})

	machine, err := runtimeInfoOf(m.newRun()).GetMachineID()
	id := machine.ID

	require.Equal(t, "per-user-id", id)
	requireUnreadableFileReported(t, err, m.shared.machineWide)
}

func TestAcceptance_FilesThatAreMissingOrHoldNoValidIDAreNotReported(t *testing.T) {
	m := newIsolatedMachine(t)
	seed(t, m.shared.machineWide, "{not json")
	seed(t, m.studio.machineWide, "not a valid id")
	seed(t, m.studio.perUser, strings.Repeat("a", maxIDFileSize+1))

	machine, err := runtimeInfoOf(m.newRun()).GetMachineID()
	id := machine.ID

	require.NoError(t, err)
	require.True(t, valid(id))
}

func TestAcceptance_UnwritablePerUserDirectoryWithoutUnreadableFilesIsReportedAsNotPersisted(t *testing.T) {
	m := newIsolatedMachine(t)
	perUserDir := filepath.Dir(m.shared.perUser)
	require.NoError(t, os.MkdirAll(perUserDir, 0o755))
	makeUnwritable(t, perUserDir)

	machine, err := runtimeInfoOf(m.newRun()).GetMachineID()
	id := machine.ID

	require.Empty(t, id)
	require.ErrorIs(t, err, runtimeinfo.ErrNoMachineID)
	requireNotPersistedReported(t, err, perUserDir)
}

func TestAcceptance_NotPersistedDetailIsOneLineWhenMachineWideAndPerUserWritesFail(t *testing.T) {
	m := newIsolatedMachine(t)
	machineWideDir := filepath.Dir(m.shared.machineWide)
	require.NoError(t, os.MkdirAll(machineWideDir, 0o755))
	makeUnwritable(t, machineWideDir)
	m.blockEverySharedFileLocation(t)

	_, err := runtimeInfoOf(m.newRun()).GetMachineID()

	var notPersisted snyk_errors.Error
	for _, e := range catalogErrorsIn(err) {
		if e.ErrorCode == "SNYK-CLI-0031" {
			notPersisted = e
		}
	}
	require.Equal(t, "SNYK-CLI-0031", notPersisted.ErrorCode, "no SNYK-CLI-0031 error in %v", err)
	require.Contains(t, notPersisted.Detail, machineWideDir)
	require.Contains(t, notPersisted.Detail, filepath.Dir(filepath.Dir(m.shared.perUser)))
	require.NotContains(t, notPersisted.Detail, "\n")
}
