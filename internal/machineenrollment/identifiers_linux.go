package machineenrollment

import "context"

func readSerialNumbers(_ context.Context) ([]string, error) {
	return readDMISerials("/sys/class/dmi/id"), nil
}
