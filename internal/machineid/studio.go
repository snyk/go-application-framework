package machineid

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"github.com/rs/zerolog"
)

// defaultStudioDeviceIDPaths returns the machine-wide and per-user locations of the Snyk Studio
// device-id file.
func defaultStudioDeviceIDPaths() pathPair {
	return studioDeviceIDPathsFor(runtime.GOOS)
}

func studioDeviceIDPathsFor(goos string) pathPair {
	switch goos {
	case "windows":
		return pathPair{
			machineWide: absOrEmpty(filepath.Join(os.Getenv("ProgramData"), "Snyk", "studio", "device-id")),
			perUser:     absOrEmpty(filepath.Join(os.Getenv("LOCALAPPDATA"), "Snyk", "studio", "device-id")),
		}
	case "darwin":
		home, _ := os.UserHomeDir() //nolint:errcheck // best-effort; an empty home is handled by absOrEmpty below
		return pathPair{
			machineWide: "/Library/Application Support/snyk-studio/device-id",
			perUser:     absOrEmpty(filepath.Join(home, ".snyk-studio", "device-id")),
		}
	default:
		home, _ := os.UserHomeDir() //nolint:errcheck // best-effort; an empty home is handled by absOrEmpty below
		return pathPair{
			machineWide: "/var/lib/snyk-studio/device-id",
			perUser:     absOrEmpty(filepath.Join(home, ".snyk-studio", "device-id")),
		}
	}
}

// readStudioDeviceID returns the first valid id from the machine-wide, then the per-user, Snyk Studio
// device-id file, so the result does not depend on the user when the two disagree. Only trailing
// whitespace is trimmed (a trailing newline is a file artifact) before validation.
func readStudioDeviceID(paths pathPair, logger *zerolog.Logger) (id string, path string, ok bool) {
	for _, p := range []string{paths.machineWide, paths.perUser} {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			logger.Debug().Err(err).Str("path", p).Msg("machine id: Snyk Studio device-id file candidate could not be read")
			continue
		}
		candidate := strings.TrimRightFunc(string(data), unicode.IsSpace)
		if blank(candidate) {
			logger.Debug().Str("path", p).Msg("machine id: Snyk Studio device-id file candidate was empty")
			continue
		}
		if reason, ok := validate(candidate); !ok {
			logger.Debug().Str("path", p).Str("reason", reason).Msg("machine id: Snyk Studio device-id file candidate failed validation")
			continue
		}
		return candidate, p, true
	}
	return "", "", false
}
