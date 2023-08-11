//go:build !boringcrypto && !goexperiment.systemcrypto && !goexperiment.cngcrypto && !goexperiment.opensslcrypto

package fips

import (
	"fmt"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Validate(config configuration.Configuration) error {
	var err error

	if config.GetBool(configuration.FIPS_ENABLED) {
		err = fmt.Errorf("FIPS is enabled but the application doesn't support it")
	}

	return err
}

func IsAvailable() bool {
	return false
}
