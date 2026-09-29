package machineid

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"github.com/rs/zerolog"
)

// legacyDeviceIDPaths is a variable so tests can point it at temporary files.
var legacyDeviceIDPaths = defaultLegacyDeviceIDPaths

// defaultLegacyDeviceIDPaths returns the well-known locations of the bare-string device-id file
// written by the studio product that predates the shared machine-id file. Both variants are
// checked so a machine that only ever ran studio for one user, or only as a service, still has its
// existing identity picked up rather than minting a second one.
func defaultLegacyDeviceIDPaths() pathPair {
	switch runtime.GOOS {
	case "windows":
		return pathPair{
			machineWide: absOrEmpty(filepath.Join(os.Getenv("ProgramData"), "Snyk", "studio", "device-id")),
			perUser:     absOrEmpty(filepath.Join(os.Getenv("LOCALAPPDATA"), "Snyk", "studio", "device-id")),
		}
	case "darwin":
		home, _ := os.UserHomeDir() //nolint:errcheck // best-effort; an empty home is handled by absOrEmpty below
		return pathPair{
			machineWide: "/Library/Application Support/Snyk/studio/device-id",
			perUser:     absOrEmpty(filepath.Join(home, ".snyk", "studio", "device-id")),
		}
	default:
		home, _ := os.UserHomeDir() //nolint:errcheck // best-effort; an empty home is handled by absOrEmpty below
		return pathPair{
			machineWide: "/etc/snyk/studio/device-id",
			perUser:     absOrEmpty(filepath.Join(home, ".snyk", "studio", "device-id")),
		}
	}
}

// readLegacyDeviceID looks for a legacy bare-string device-id file at the machine-wide location
// first, then the per-user one, so that two variants left behind by different studio install modes
// that disagree resolve to the machine-wide value rather than an arbitrary one. The file's content
// is trimmed of trailing whitespace only, since a trailing newline is a file-format artifact rather
// than part of the identifier, and validated like every other candidate.
func readLegacyDeviceID(paths pathPair, logger *zerolog.Logger) (id string, path string, ok bool) {
	logger = effectiveLogger(logger)
	for _, p := range []string{paths.machineWide, paths.perUser} {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			logger.Debug().Err(err).Str("path", p).Msg("machine id: legacy device-id file candidate could not be read")
			continue
		}
		candidate := strings.TrimRightFunc(string(data), unicode.IsSpace)
		if blank(candidate) {
			logger.Debug().Str("path", p).Msg("machine id: legacy device-id file candidate was empty")
			continue
		}
		if !valid(candidate) {
			logger.Debug().Str("path", p).Str("reason", invalidReason(candidate)).Msg("machine id: legacy device-id file candidate failed validation")
			continue
		}
		return candidate, p, true
	}
	return "", "", false
}
