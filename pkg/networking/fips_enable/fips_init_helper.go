package fips_enable

// Don't import anything

const godebugEnvVarName = "GODEBUG"
const envVarValueEnable = "fips140="
const envVarOnValue = "on"
const envVarOffValue = "off"

func setFipState(existingValue string, enabled bool) string {
	if len(existingValue) > 0 {
		existingValue = "," + existingValue
	}

	enabledString := envVarOnValue
	if !enabled {
		enabledString = envVarOffValue
	}

	existingValue = envVarValueEnable + enabledString + existingValue
	return existingValue
}
