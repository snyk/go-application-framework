//go:build boringcrypto || goexperiment.systemcrypto || goexperiment.cngcrypto || goexperiment.opensslcrypto

package fips

import "github.com/snyk/go-application-framework/pkg/configuration"
import _ "crypto/tls/fipsonly"

func Validate(configuration configuration.Configuration) error {
	return nil
}

func IsAvailable() bool {
	return true
}
