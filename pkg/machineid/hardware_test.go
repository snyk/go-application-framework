package machineid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestReadSerialCandidate_DisabledNeverReadsTheHardware(t *testing.T) {
	original := readHardwareSerialFunc
	readHardwareSerialFunc = func(context.Context, *zerolog.Logger) (string, bool) {
		t.Fatal("must not read the hardware serial number when the option is disabled")
		return "", false
	}
	t.Cleanup(func() { readHardwareSerialFunc = original })

	require.Equal(t, "", readSerialCandidate(false, nil))
}

func TestReadSerialCandidate_TrimsAndAcceptsAValidCandidate(t *testing.T) {
	original := readHardwareSerialFunc
	readHardwareSerialFunc = func(context.Context, *zerolog.Logger) (string, bool) {
		return "  5CG1234ABC  ", true
	}
	t.Cleanup(func() { readHardwareSerialFunc = original })

	require.Equal(t, "5CG1234ABC", readSerialCandidate(true, nil))
}

func TestReadSerialCandidate_AbsentReaderFallsThrough(t *testing.T) {
	original := readHardwareSerialFunc
	readHardwareSerialFunc = func(context.Context, *zerolog.Logger) (string, bool) {
		return "", false
	}
	t.Cleanup(func() { readHardwareSerialFunc = original })

	require.Equal(t, "", readSerialCandidate(true, nil))
}

// TestReadSerialCandidate_PlaceholderFallsThrough covers the single most likely real-world failure
// mode: a manufacturer placeholder in place of a real serial number must not become the machine
// identifier.
func TestReadSerialCandidate_PlaceholderFallsThrough(t *testing.T) {
	original := readHardwareSerialFunc
	readHardwareSerialFunc = func(context.Context, *zerolog.Logger) (string, bool) {
		return "None", true
	}
	t.Cleanup(func() { readHardwareSerialFunc = original })

	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	require.Equal(t, "", readSerialCandidate(true, &logger))
	require.Contains(t, logs.String(), "placeholder")
	require.NotContains(t, logs.String(), "None", "the rejected raw candidate value must never be logged")
}

// TestReadSerialCandidate_MultiWordPlaceholderFallsThrough covers a manufacturer placeholder that
// contains spaces: it is rejected by the character-set check rather than the placeholder check, but
// the observable outcome that matters is the same, it never becomes the machine identifier.
func TestReadSerialCandidate_MultiWordPlaceholderFallsThrough(t *testing.T) {
	original := readHardwareSerialFunc
	readHardwareSerialFunc = func(context.Context, *zerolog.Logger) (string, bool) {
		return "To be filled by O.E.M.", true
	}
	t.Cleanup(func() { readHardwareSerialFunc = original })

	var logs bytes.Buffer
	logger := zerolog.New(&logs).Level(zerolog.DebugLevel)
	require.Equal(t, "", readSerialCandidate(true, &logger))
	require.Contains(t, logs.String(), "hardware serial number failed validation")
	require.NotContains(t, logs.String(), "O.E.M.", "the rejected raw candidate value must never be logged")
}

func TestReadHostnameCandidate_DisabledNeverReadsTheHostname(t *testing.T) {
	original := hostnameFunc
	hostnameFunc = func() (string, error) {
		t.Fatal("must not read the hostname when the option is disabled")
		return "", nil
	}
	t.Cleanup(func() { hostnameFunc = original })

	require.Equal(t, "", readHostnameCandidate(false, nil))
}

func TestReadHostnameCandidate_TrimsAndAcceptsAValidCandidate(t *testing.T) {
	original := hostnameFunc
	hostnameFunc = func() (string, error) { return "  my-laptop.local  ", nil }
	t.Cleanup(func() { hostnameFunc = original })

	require.Equal(t, "my-laptop.local", readHostnameCandidate(true, nil))
}

func TestReadHostnameCandidate_LookupFailureFallsThrough(t *testing.T) {
	original := hostnameFunc
	hostnameFunc = func() (string, error) { return "", errors.New("simulated failure") }
	t.Cleanup(func() { hostnameFunc = original })

	require.Equal(t, "", readHostnameCandidate(true, nil))
}

func TestReadHostnameCandidate_InvalidValueFallsThrough(t *testing.T) {
	original := hostnameFunc
	hostnameFunc = func() (string, error) { return "host name with spaces", nil }
	t.Cleanup(func() { hostnameFunc = original })

	require.Equal(t, "", readHostnameCandidate(true, nil))
}

func TestRecordHostnameMetadata_WritesHostnameFieldToTheSharedFile(t *testing.T) {
	machineWideDir := filepath.Join(t.TempDir(), "machine-wide", "snyk")
	perUserDir := filepath.Join(t.TempDir(), "per-user", "snyk")
	original := sharedFilePaths
	sharedFilePaths = func() pathPair {
		return pathPair{
			machineWide: filepath.Join(machineWideDir, "machine-id.json"),
			perUser:     filepath.Join(perUserDir, "machine-id.json"),
		}
	}
	t.Cleanup(func() { sharedFilePaths = original })

	recordHostnameMetadata("my-laptop.local", "test-writer", nil)

	data, err := os.ReadFile(selectWritePath(sharedFilePaths(), nil))
	require.NoError(t, err)
	var raw map[string]any
	require.NoError(t, json.Unmarshal(data, &raw))
	require.Equal(t, "my-laptop.local", raw["hostname"])
}

func TestRecordHostnameMetadata_BlankHostnameWritesNothing(t *testing.T) {
	machineWideDir := filepath.Join(t.TempDir(), "machine-wide", "snyk")
	perUserDir := filepath.Join(t.TempDir(), "per-user", "snyk")
	original := sharedFilePaths
	sharedFilePaths = func() pathPair {
		return pathPair{
			machineWide: filepath.Join(machineWideDir, "machine-id.json"),
			perUser:     filepath.Join(perUserDir, "machine-id.json"),
		}
	}
	t.Cleanup(func() { sharedFilePaths = original })

	recordHostnameMetadata("", "test-writer", nil)

	require.NoFileExists(t, sharedFilePaths().perUser, "no file should be written when there is no hostname to record")
}
