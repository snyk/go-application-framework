// Package machineenrollment enrolls a device as a machine principal using a single-use join key an
// admin issued for it, and authenticates it afterward. The server answers with an OAuth client_id
// bound to a newly generated RSA key (RS256), which then authenticates with private_key_jwt client
// assertions, so the join key itself is only used once.
package machineenrollment

const (
	// CONFIG_KEY_CLIENT_ID holds the OAuth client_id of the enrolled machine.
	CONFIG_KEY_CLIENT_ID = "INTERNAL_MACHINE_CLIENT_ID"
	// CONFIG_KEY_CLIENT_KEY_FILE holds the path of the PEM file with the machine client's private key.
	CONFIG_KEY_CLIENT_KEY_FILE = "INTERNAL_MACHINE_CLIENT_KEY_FILE"
	// CONFIG_KEY_MACHINE_ID holds the ID of the enrolled machine, for display only.
	CONFIG_KEY_MACHINE_ID = "INTERNAL_MACHINE_ID"
)
