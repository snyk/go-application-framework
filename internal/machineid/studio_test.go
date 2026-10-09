package machineid

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultStudioDeviceIDPathsArePinnedPerOS(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Setenv("ProgramData", `C:\ProgramData`)
		t.Setenv("LOCALAPPDATA", `C:\Users\someone\AppData\Local`)
		require.Equal(t, pathPair{
			machineWide: `C:\ProgramData\Snyk\studio\device-id`,
			perUser:     `C:\Users\someone\AppData\Local\Snyk\studio\device-id`,
		}, studioDeviceIDPathsFor("windows"))
		return
	}
	home := t.TempDir()
	t.Setenv("HOME", home)

	require.Equal(t, pathPair{
		machineWide: "/var/lib/snyk-studio/device-id",
		perUser:     filepath.Join(home, ".snyk-studio", "device-id"),
	}, studioDeviceIDPathsFor("linux"))
	require.Equal(t, pathPair{
		machineWide: "/Library/Application Support/snyk-studio/device-id",
		perUser:     filepath.Join(home, ".snyk-studio", "device-id"),
	}, studioDeviceIDPathsFor("darwin"))
}
