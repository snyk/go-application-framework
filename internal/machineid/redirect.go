package machineid

import "path/filepath"

// RedirectForTest makes every location this package reads or writes (the shared file and the Snyk
// Studio device-id file, machine-wide and per-user) resolve under root, so tests in other packages
// never touch a real machine-wide path. The machine-wide directories are not created, so writes land
// in the returned per-user shared file. Call restore to go back to the default locations. It is not
// safe for tests running in parallel.
func RedirectForTest(root string) (perUserSharedFile string, restore func()) {
	shared := pathPair{
		machineWide: filepath.Join(root, "machine", "Snyk", sharedFileName),
		perUser:     filepath.Join(root, "user", ".snyk", sharedFileName),
	}
	studio := pathPair{
		machineWide: filepath.Join(root, "machine", "snyk-studio", "device-id"),
		perUser:     filepath.Join(root, "user", ".snyk-studio", "device-id"),
	}
	sharedFilePaths = func() pathPair { return shared }
	studioDeviceIDPaths = func() pathPair { return studio }
	return shared.perUser, func() {
		sharedFilePaths = defaultSharedFilePaths
		studioDeviceIDPaths = defaultStudioDeviceIDPaths
	}
}
