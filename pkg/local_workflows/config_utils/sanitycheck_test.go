package config_utils

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jws"

	"github.com/snyk/go-application-framework/pkg/auth"
	"github.com/snyk/go-application-framework/pkg/configuration"
)

func Test_CheckSanity_ApiUrl(t *testing.T) {
	expectedAudience := "hello.world"
	header := &jws.Header{}
	claims := &jws.ClaimSet{
		Aud: expectedAudience,
	}
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	accessToken, err := jws.Encode(header, claims, pk)
	assert.NoError(t, err)

	token := oauth2.Token{
		AccessToken: accessToken,
	}

	tokenBytes, err := json.Marshal(token)
	assert.NoError(t, err)

	t.Run("different url from auth material", func(t *testing.T) {
		// Create a configuration with duplicate keys
		config := configuration.NewWithOpts()
		config.Set(configuration.API_URL, "https://api1.example.com")
		config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, string(tokenBytes))

		result := CheckSanity(config)

		expectedDescription := fmt.Sprintf(configCheckMismatchedUrlMsg, "SNYK_API")
		assert.Len(t, result, 1)
		assert.Contains(t, result[0].Description, expectedDescription)
	})

	t.Run("same url auth material", func(t *testing.T) {
		// Create a configuration with duplicate keys
		config := configuration.NewWithOpts()
		config.Set(configuration.API_URL, expectedAudience)
		config.Set(auth.CONFIG_KEY_OAUTH_TOKEN, string(tokenBytes))

		result := CheckSanity(config)
		assert.Len(t, result, 0)
	})

	t.Run("no auth material", func(t *testing.T) {
		// Create a configuration with duplicate keys
		config := configuration.NewWithOpts()
		config.Set(configuration.API_URL, expectedAudience)

		result := CheckSanity(config)
		assert.Len(t, result, 0)
	})
}

func Test_CheckSanity_Token(t *testing.T) {
	alternativeTokenVariable := "my_token"
	expectedDescription := "Possible unexpected behavior, the following configuration values might override each other "

	config := configuration.NewWithOpts()
	config.Set(configuration.AUTHENTICATION_TOKEN, "random1")
	config.Set(alternativeTokenVariable, "random2")
	config.AddAlternativeKeys(configuration.AUTHENTICATION_TOKEN, []string{alternativeTokenVariable})

	result := CheckSanity(config)
	assert.Len(t, result, 1)

	assert.Contains(t, result[0].Description, expectedDescription)
}
