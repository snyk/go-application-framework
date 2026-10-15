// Package machineenrollment enrolls a device as a machine principal and authenticates it
// afterwards.
//
// A machine enrolls in one of two ways. Attested enrollment proves, in one request, that the device
// holds the private key of an identity certificate issued by its device management CA (read from
// the platform's keychain) and that it holds a newly generated RS256 key. Join-token enrollment
// presents a single-use token an admin issued for the machine instead of the certificate, so it
// works on any platform. Either way the server answers with an OAuth client_id bound to the RS256
// key, which then authenticates with private_key_jwt client assertions, so the certificate or token
// is only used once.
package machineenrollment

const (
	// CONFIG_KEY_CLIENT_ID holds the OAuth client_id of the enrolled machine.
	CONFIG_KEY_CLIENT_ID = "INTERNAL_MACHINE_CLIENT_ID"
	// CONFIG_KEY_CLIENT_KEY_FILE holds the path of the PEM file with the machine client's private key.
	CONFIG_KEY_CLIENT_KEY_FILE = "INTERNAL_MACHINE_CLIENT_KEY_FILE"
	// CONFIG_KEY_MACHINE_ID holds the ID of the enrolled machine, for display only.
	CONFIG_KEY_MACHINE_ID = "INTERNAL_MACHINE_ID"
)
