// Package machineenrollment enrolls a managed device as a machine principal and authenticates it
// afterwards.
//
// Enrollment proves two things to the server in one request: that the device holds the private key
// of an identity certificate issued by its device management CA (read from the platform's
// keychain), and that it holds a newly generated ES256 key. The server answers with an OAuth
// client_id bound to the ES256 key, which then authenticates with private_key_jwt client
// assertions, so the identity certificate is only used once.
package machineenrollment

const (
	// CONFIG_KEY_CLIENT_ID holds the OAuth client_id of the enrolled machine.
	CONFIG_KEY_CLIENT_ID = "INTERNAL_MACHINE_CLIENT_ID"
	// CONFIG_KEY_CLIENT_KEY_FILE holds the path of the PEM file with the machine client's private key.
	CONFIG_KEY_CLIENT_KEY_FILE = "INTERNAL_MACHINE_CLIENT_KEY_FILE"
	// CONFIG_KEY_MACHINE_ID holds the ID of the enrolled machine, for display only.
	CONFIG_KEY_MACHINE_ID = "INTERNAL_MACHINE_ID"
)
