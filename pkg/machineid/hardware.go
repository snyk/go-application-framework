package machineid

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// hardwareSerialTimeout bounds how long the platform-specific hardware serial number read may
// take, so a hung subprocess (macOS) or blocking file read cannot delay resolution indefinitely. It
// is a variable so tests can substitute a short bound instead of waiting out the real timeout.
var hardwareSerialTimeout = 5 * time.Second

// readHardwareSerialFunc is the platform-specific hardware serial number reader selected by build
// tag (see serial_darwin.go, serial_linux.go, serial_windows.go, serial_other.go). It is a variable
// so tests can substitute a fake reader on any platform.
var readHardwareSerialFunc = readHardwareSerial

// hostnameFunc looks up the machine's hostname. It is a variable so tests can substitute a fake
// value or failure without depending on the sandbox's actual hostname.
var hostnameFunc = os.Hostname

// readSerialCandidate reads and validates the platform hardware serial number, returning "" if the
// option is disabled, no serial could be read, or the value failed validation — including matching
// a placeholder a manufacturer emits in place of a real serial (e.g. "To be filled by O.E.M."). The
// raw candidate is never logged: a rejected value is logged by reason only, like every other
// rejected candidate in this package.
func readSerialCandidate(enabled bool, logger *zerolog.Logger) string {
	logger = effectiveLogger(logger)
	if !enabled {
		logger.Debug().Msg("machine id: hardware identity disabled, skipping hardware serial number")
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), hardwareSerialTimeout)
	defer cancel()
	raw, ok := readHardwareSerialFunc(ctx, logger)
	if !ok {
		logger.Debug().Msg("machine id: hardware serial number is absent")
		return ""
	}
	candidate := strings.TrimSpace(raw)
	if blank(candidate) {
		logger.Debug().Msg("machine id: hardware serial number is absent")
		return ""
	}
	if !valid(candidate) {
		logger.Debug().Str("reason", invalidReason(candidate)).Msg("machine id: hardware serial number failed validation")
		return ""
	}
	logger.Debug().Msg("machine id: hardware serial number is a usable candidate")
	return candidate
}

// readHostnameCandidate reads and validates the machine's hostname, returning "" if the option is
// disabled, the hostname could not be looked up, or it failed validation.
func readHostnameCandidate(enabled bool, logger *zerolog.Logger) string {
	logger = effectiveLogger(logger)
	if !enabled {
		logger.Debug().Msg("machine id: hardware identity disabled, skipping hostname")
		return ""
	}
	raw, err := hostnameFunc()
	if err != nil {
		logger.Debug().Err(err).Msg("machine id: hostname lookup failed")
		return ""
	}
	candidate := strings.TrimSpace(raw)
	if blank(candidate) {
		logger.Debug().Msg("machine id: hostname lookup returned no value")
		return ""
	}
	if !valid(candidate) {
		logger.Debug().Str("reason", invalidReason(candidate)).Msg("machine id: hostname failed validation")
		return ""
	}
	logger.Debug().Msg("machine id: hostname is a usable candidate")
	return candidate
}

// recordHostnameMetadata best-effort records a hostname read during this resolution into the
// shared file, so other Snyk products on the machine can use it for correlation even when it did
// not win as the machine id itself (a higher-precedence source, e.g. the shared file or a legacy
// device-id file, can still win over it). A serial number needs no equivalent here: whenever a
// valid one is read it always wins as the machine id itself (see resolve), so adopt already stamps
// the shared file's serial_number field as part of that same write.
func recordHostnameMetadata(hostname, writer string, logger *zerolog.Logger) {
	if blank(hostname) {
		return
	}
	logger = effectiveLogger(logger)
	paths := sharedFilePaths()
	path := selectWritePath(paths, logger)
	err := writeSharedFileValue(path, path == paths.perUser, writer, func(sf *sharedFile) {
		sf.Hostname = hostname
	}, logger)
	if err != nil {
		logger.Debug().Err(err).Msg("machine id: failed to record hostname in shared file")
	}
}
