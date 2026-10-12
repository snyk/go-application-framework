//go:build !darwin || !cgo

package machineenrollment

// SystemKeychain returns a keychain that has no identities: device identities are only supported
// on macOS builds with cgo.
func SystemKeychain() Keychain {
	return unsupportedKeychain{}
}

type unsupportedKeychain struct{}

func (unsupportedKeychain) Identity([][]byte) (DeviceIdentity, error) {
	return nil, ErrUnsupported
}

func (unsupportedKeychain) DeviceInfo() DeviceInfo {
	return DeviceInfo{}
}
