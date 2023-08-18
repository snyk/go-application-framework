//go:build boringcrypto || goexperiment.systemcrypto || goexperiment.cngcrypto || goexperiment.opensslcrypto

package fips

import _ "github.com/snyk/go-application-framework/pkg/networking/fips_enable"

import (
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_FIPS_CRYPTO_Auto_Enabled(t *testing.T) {
	config := configuration.NewInMemory()
	assert.True(t, config.GetBool(configuration.FIPS_ENABLED))
}

func Test_FIPS_CRYPTO_IsAvailable(t *testing.T) {
	assert.True(t, IsAvailable())
}
