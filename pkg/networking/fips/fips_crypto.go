//go:build boringcrypto || goexperiment.systemcrypto || goexperiment.cngcrypto || goexperiment.opensslcrypto

package fips

import _ "crypto/tls/fipsonly"

func IsAvailable() bool {
	return true
}
