package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jws"
)

func getAccessTokenWithSingleAudienceClaim(t *testing.T, audience string) string {
	t.Helper()
	header := &jws.Header{}
	claims := &jws.ClaimSet{
		Aud: audience,
	}
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	accessToken, err := jws.Encode(header, claims, pk)
	assert.NoError(t, err)

	return accessToken
}

func getAccessTokenWithMultpleAudienceClaim() string {
	return "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJhdWQiOlsiaHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20iXX0.hWq0fKukObQSkphAdyEC7-m4jXIb4VdWyQySmmgy0GU"
}

func Test_ReadAudience_SingleClaim(t *testing.T) {
	expectedString := "api.eu.snyk.io"
	expectedAudience := []string{expectedString}
	token := oauth2.Token{
		AccessToken: getAccessTokenWithSingleAudienceClaim(t, expectedString),
	}

	actualAudience, err := readAudience(&token)
	assert.NoError(t, err)

	assert.Equal(t, expectedAudience, actualAudience)
}

func Test_ReadAudience_ArrayClaim(t *testing.T) {
	expectedAudience := []string{"https://api.example.com"}
	token := oauth2.Token{
		AccessToken: getAccessTokenWithMultpleAudienceClaim(),
	}

	actualAudience, err := readAudience(&token)
	assert.NoError(t, err)

	assert.Equal(t, expectedAudience, actualAudience)
}

func Test_GetAudienceClaimFromOauthToken(t *testing.T) {
	t.Run("Happy path", func(t *testing.T) {
		expectedString := "api.eu.snyk.io"
		expectedAudience := []string{expectedString}
		token := oauth2.Token{
			AccessToken: getAccessTokenWithSingleAudienceClaim(t, expectedString),
		}

		tokenBytes, err := json.Marshal(token)
		assert.NoError(t, err)

		actualClaims, err := GetAudienceClaimFromOauthToken(string(tokenBytes))
		assert.NoError(t, err)
		assert.Equal(t, expectedAudience, actualClaims)
	})

	t.Run("empty token string", func(t *testing.T) {
		expectedAudience := []string{}

		actualClaims, err := GetAudienceClaimFromOauthToken("")
		assert.NoError(t, err)
		assert.Equal(t, expectedAudience, actualClaims)
	})

	t.Run("random string value", func(t *testing.T) {
		expectedAudience := []string{}

		actualClaims, err := GetAudienceClaimFromOauthToken("aihsfdhajksh")
		assert.Error(t, err)
		assert.Equal(t, expectedAudience, actualClaims)
	})
}
