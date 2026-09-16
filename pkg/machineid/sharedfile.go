package machineid

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/gofrs/flock"

	"github.com/snyk/go-application-framework/internal/fileperms"
)

// SharedFile is the schema of the machine-identity file shared by every Snyk product on the
// machine. GAF only ever writes machine_id and identifier_source; the remaining fields may be
// populated by other tooling and are preserved, not interpreted, by GAF.
type SharedFile struct {
	MachineID        string `json:"machine_id,omitempty"`
	IdentifierSource string `json:"identifier_source,omitempty"`
	SerialNumber     string `json:"serial_number,omitempty"`
	Hostname         string `json:"hostname,omitempty"`
	SnykMachineID    string `json:"snyk_machine_id,omitempty"`
}

// pathPair is the machine-wide and per-user candidate locations for the shared file.
type pathPair struct {
	machineWide string
	perUser     string
}

// sharedFilePaths is a variable so tests can point it at temporary directories; the machine-wide
// path on Linux and macOS is a fixed OS path that a test process cannot write to without root.
var sharedFilePaths = defaultSharedFilePaths

func defaultSharedFilePaths() pathPair {
	switch runtime.GOOS {
	case "windows":
		return pathPair{
			machineWide: filepath.Join(os.Getenv("ProgramData"), "snyk", "machine-id.json"),
			perUser:     filepath.Join(os.Getenv("APPDATA"), "snyk", "machine-id.json"),
		}
	case "darwin":
		home, _ := os.UserHomeDir() //nolint:errcheck // best-effort; an empty home yields a relative fallback path
		return pathPair{
			machineWide: "/Library/Application Support/snyk/machine-id.json",
			perUser:     filepath.Join(home, "Library", "Application Support", "snyk", "machine-id.json"),
		}
	default:
		xdgConfigHome := os.Getenv("XDG_CONFIG_HOME")
		if xdgConfigHome == "" {
			home, _ := os.UserHomeDir() //nolint:errcheck // best-effort; an empty home yields a relative fallback path
			xdgConfigHome = filepath.Join(home, ".config")
		}
		return pathPair{
			machineWide: "/etc/snyk/machine-id.json",
			perUser:     filepath.Join(xdgConfigHome, "snyk", "machine-id.json"),
		}
	}
}

// readSharedFile reads the first of the machine-wide or per-user candidates that parses
// successfully, machine-wide taking precedence. A missing or unparsable file is not an error; it
// is simply absent.
func readSharedFile(paths pathPair) *SharedFile {
	for _, p := range []string{paths.machineWide, paths.perUser} {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var sf SharedFile
		if err := json.Unmarshal(data, &sf); err != nil {
			continue
		}
		return &sf
	}
	return nil
}

// dirWritable reports whether the current process can create files in dir, without leaving one
// behind.
func dirWritable(dir string) bool {
	probe := filepath.Join(dir, ".snyk-write-probe-"+strconv.Itoa(os.Getpid()))
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fileperms.FILEPERM_666)
	if err != nil {
		return false
	}
	_ = f.Close()
	_ = os.Remove(probe)
	return true
}

// selectWritePath picks the machine-wide path when its directory already exists and is writable
// by the current process, otherwise the per-user path. It never creates the machine-wide
// directory.
func selectWritePath(paths pathPair) string {
	dir := filepath.Dir(paths.machineWide)
	if info, err := os.Stat(dir); err == nil && info.IsDir() && dirWritable(dir) {
		return paths.machineWide
	}
	return paths.perUser
}

// writeSharedFileValue serializes writers to path with flock, then applies mutate to the file's
// current contents (or a zero SharedFile if it does not yet exist) and writes back the result.
// createDir controls whether the parent directory may be created; it must be false for the
// machine-wide path, whose directory GAF never creates.
func writeSharedFileValue(path string, createDir bool, mutate func(*SharedFile)) error {
	// The lock file lives next to path, so its directory must exist before flock creates it;
	// MkdirAll has to run before Lock, not after.
	if createDir {
		if err := os.MkdirAll(filepath.Dir(path), fileperms.FILEPERM_755); err != nil {
			return err
		}
	}

	lock := flock.New(path + ".lock")
	if err := lock.Lock(); err != nil {
		return err
	}
	defer func() { _ = lock.Unlock() }() //nolint:errcheck // unlock errors are ignored, matching syncTokenRefresh in pkg/auth

	sf := SharedFile{}
	if data, err := os.ReadFile(path); err == nil {
		//nolint:errcheck // an unparsable existing file is treated as absent; mutate below fills sf from scratch
		_ = json.Unmarshal(data, &sf)
	}

	mutate(&sf)

	data, err := json.Marshal(sf)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, fileperms.FILEPERM_666)
}

// removeSharedFileValue clears machine_id and identifier_source from the shared file at path,
// leaving any other fields (populated by other tooling) untouched. A missing file is not an error.
func removeSharedFileValue(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	return writeSharedFileValue(path, false, func(sf *SharedFile) {
		sf.MachineID = ""
		sf.IdentifierSource = ""
	})
}
