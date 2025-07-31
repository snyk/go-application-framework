//go:build boringcrypto || goexperiment.systemcrypto || goexperiment.cngcrypto || goexperiment.opensslcrypto

// This package can be used for its side effect. When imported as the very first step of
// the application it either enabled or disables FIPS by default.
package fips_enable

// Don't import anything else
import "os"

func init() {
	existingValue := os.Getenv(godebugEnvVarName)
	existingValue = setFipState(existingValue, true)
	os.Setenv(godebugEnvVarName, existingValue)
}
