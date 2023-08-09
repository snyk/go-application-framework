//go:build boringcrypto || goexperiment.systemcrypto || goexperiment.cngcrypto || goexperiment.opensslcrypto

package fips

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_FIPS_CRYPTO_Validate(t *testing.T) {
	config := configuration.NewInMemory()
	config.Set(configuration.FIPS_ENABLED, "1")
	assert.Nil(t, Validate(config))

	config.Set(configuration.FIPS_ENABLED, "0")
	assert.Nil(t, Validate(config))
}

func Test_FIPS_CRYPTO_IsAvailable(t *testing.T) {
	assert.True(t, IsAvailable())
}
