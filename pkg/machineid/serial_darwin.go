//go:build darwin

package machineid

import (
	"context"
	"os/exec"

	"github.com/rs/zerolog"
)

// ioregPath is the absolute path to ioreg, invoked instead of relying on PATH resolution since this
// package can run on the startup path of a host process (e.g. a JSON-RPC-over-stdio server) whose
// environment should not influence which binary gets executed.
const ioregPath = "/usr/sbin/ioreg"

// readHardwareSerial reads the platform serial number via ioreg, bounded by ctx so a hung
// subprocess cannot delay resolution indefinitely. Neither stdin nor stderr is inherited from this
// process: ioreg needs no input, and its diagnostic output has no reader that would benefit from
// seeing it inherited into a host process's own stderr.
func readHardwareSerial(ctx context.Context, logger *zerolog.Logger) (string, bool) {
	logger = effectiveLogger(logger)
	cmd := exec.CommandContext(ctx, ioregPath, "-rd1", "-c", "IOPlatformExpertDevice")
	output, err := cmd.Output()
	if err != nil {
		logger.Debug().Err(err).Msg("machine id: ioreg failed to produce hardware serial number output")
		return "", false
	}
	return parseIoregPlatformSerial(output)
}
