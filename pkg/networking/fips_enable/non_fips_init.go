//go:build !boringcrypto && !goexperiment.systemcrypto && !goexperiment.cngcrypto && !goexperiment.opensslcrypto

package fips_enable

// Don't import anything else
import "os"

func init() {
	existingValue := os.Getenv(godebugEnvVarName)
	existingValue = setFipState(existingValue, false)
	os.Setenv(godebugEnvVarName, existingValue)
}
