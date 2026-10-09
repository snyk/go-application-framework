package machineid

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadIDFileReadsASmallRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-id")
	require.NoError(t, os.WriteFile(path, []byte("an-id\n"), 0o600))

	data, err := readIDFile(path)

	require.NoError(t, err)
	require.Equal(t, "an-id\n", string(data))
}

func TestReadIDFileRejectsADirectory(t *testing.T) {
	_, err := readIDFile(t.TempDir())

	require.ErrorIs(t, err, errNotRegularFile)
}

func TestReadIDFileRejectsAFileOverTheSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-id")
	require.NoError(t, os.WriteFile(path, []byte(strings.Repeat("a", maxIDFileSize+1)), 0o600))

	_, err := readIDFile(path)

	require.ErrorIs(t, err, errFileTooLarge)
}

func TestReadIDFileAcceptsAFileAtTheSizeLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device-id")
	require.NoError(t, os.WriteFile(path, []byte(strings.Repeat("a", maxIDFileSize)), 0o600))

	data, err := readIDFile(path)

	require.NoError(t, err)
	require.Len(t, data, maxIDFileSize)
}
