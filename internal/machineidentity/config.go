// Package machineidentity wires machine enrollment into the framework: it enrolls a device as a machine principal and authenticates it afterward.
// A machine enrolls with a device token, a single-use token an admin issued for it, or with a fleet
// key, a reusable P-256 key an admin registered for a fleet of machines, which the machine signs its
// serial numbers with. The server answers with an OAuth client_id bound to a newly generated RSA key
// (RS256), which then authenticates with private_key_jwt client assertions, so the device token or
// fleet key is only needed to enroll.
package machineidentity

const (
	// CONFIG_KEY_CLIENT_ID holds the OAuth client_id of the enrolled machine.
	CONFIG_KEY_CLIENT_ID = "INTERNAL_MACHINE_CLIENT_ID"
	// CONFIG_KEY_CLIENT_KEY_FILE holds the path of the PEM file with the machine client's private key.
	CONFIG_KEY_CLIENT_KEY_FILE = "INTERNAL_MACHINE_CLIENT_KEY_FILE"
	// CONFIG_KEY_MACHINE_ID holds the ID of the enrolled machine, for display only.
	CONFIG_KEY_MACHINE_ID = "INTERNAL_MACHINE_ID"
)
