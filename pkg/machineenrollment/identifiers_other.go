//go:build !darwin && !linux

package machineenrollment

import "context"

func readSerialNumbers(_ context.Context) ([]string, error) {
	return nil, ErrUnsupportedPlatform
}
