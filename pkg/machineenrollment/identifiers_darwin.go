package machineenrollment

import (
	"context"
	"fmt"
	"os/exec"
)

func readSerialNumbers(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return nil, fmt.Errorf("failed reading the serial number with ioreg: %w", err)
	}
	return []string{parseIoregSerial(string(out))}, nil
}
