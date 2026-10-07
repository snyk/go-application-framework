package machineid

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRedirectForTestKeepsEveryLocationUnderRootAndRestoresTheDefaults(t *testing.T) {
	root := t.TempDir()

	perUser, restore := RedirectForTest(root)

	require.Equal(t, sharedFilePaths().perUser, perUser)
	for _, p := range []string{sharedFilePaths().machineWide, sharedFilePaths().perUser, studioDeviceIDPaths().machineWide, studioDeviceIDPaths().perUser} {
		require.True(t, strings.HasPrefix(p, root+string(filepath.Separator)), "%s must be under %s", p, root)
	}

	restore()

	require.Equal(t, defaultSharedFilePaths(), sharedFilePaths())
	require.Equal(t, defaultStudioDeviceIDPaths(), studioDeviceIDPaths())
}

func TestRedirectForTestWritesLandInThePerUserSharedFile(t *testing.T) {
	perUser, restore := RedirectForTest(t.TempDir())
	t.Cleanup(restore)

	id, err := writeSharedFileID(sharedFilePaths(), "redirected-id", string(sourceGenerated), defaultWriterIdentity, nil)

	require.NoError(t, err)
	require.Equal(t, "redirected-id", id)
	require.Equal(t, "redirected-id", readFile(t, perUser).MachineID)
}
