package auth

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsAuthTypeToken(t *testing.T) {
	assert.True(t, IsAuthTypeToken("f47ac10b-58cc-4372-a567-0e02b2c3d479"))
	// PAT format
	assert.False(t, IsAuthTypeToken("snyk_uat.12345678.abcdefg-hijklmnop.qrstuvwxyz-123456"))
}

func TestIsAuthTypePAT(t *testing.T) {
	assert.True(t, IsAuthTypePAT("snyk_uat.12345678.abcdefg-hijklmnop.qrstuvwxyz-123456"))
	// legacy token format
	assert.False(t, IsAuthTypePAT("f47ac10b-58cc-4372-a567-0e02b2c3d479"))
}

func TestExtractClaimsFromPAT(t *testing.T) {
	t.Run("Valid PAT", func(t *testing.T) {
		pat := createMockPAT(t, `{"h":"api.snyk.io"}`)

		claims, err := extractClaimsFromPAT(pat)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, "api.snyk.io", claims.Hostname)
	})

	t.Run("Valid EU PAT", func(t *testing.T) {
		pat := createMockPAT(t, `{"h":"api.eu.snyk.io"}`)

		claims, err := extractClaimsFromPAT(pat)
		assert.NoError(t, err)
		assert.NotNil(t, claims)
		assert.Equal(t, "api.eu.snyk.io", claims.Hostname)
	})

	t.Run("PAT with fewer than 4 segments", func(t *testing.T) {
		pat := "snyk_test.12345678.payload"
		claims, err := extractClaimsFromPAT(pat)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid number of segments: 3")
		assert.Nil(t, claims)
	})

	t.Run("PAT with more than 4 segments", func(t *testing.T) {
		pat := "snyk_test.12345678.payload.signature.extra"
		claims, err := extractClaimsFromPAT(pat)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid number of segments: 5")
		assert.Nil(t, claims)
	})

	t.Run("PAT with invalid base64 payload", func(t *testing.T) {
		pat := "snyk_test.12345678.invalid-base64!@#$.signature"
		claims, err := extractClaimsFromPAT(pat)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode payload")
		assert.Nil(t, claims)
	})

	t.Run("PAT with invalid JSON payload", func(t *testing.T) {
		pat := createMockPAT(t, `{"j":"pat-id-123", "h":"api.snyk.io", "e":1678886400, "s":"sub-id-456`)

		claims, err := extractClaimsFromPAT(pat)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to unmarshal payload")
		assert.Nil(t, claims)
	})
}

func TestGetApiUrlFromPAT(t *testing.T) {
	t.Run("Valid PAT", func(t *testing.T) {
		pat := createMockPAT(t, `{"h":"api.snyk.io"}`)
		apiUrl, err := GetApiUrlFromPAT(pat)
		assert.NoError(t, err)
		assert.Equal(t, "https://api.snyk.io", apiUrl)
	})

	t.Run("Valid EU PAT", func(t *testing.T) {
		pat := createMockPAT(t, `{"h":"api.eu.snyk.io"}`)
		apiUrl, err := GetApiUrlFromPAT(pat)
		assert.NoError(t, err)
		assert.Equal(t, "https://api.eu.snyk.io", apiUrl)
	})

	t.Run("PAT with scheme", func(t *testing.T) {
		pat := createMockPAT(t, `{"h":"http://api.snyk.io"}`)
		apiUrl, err := GetApiUrlFromPAT(pat)
		assert.NoError(t, err)
		assert.Equal(t, "http://api.snyk.io", apiUrl)
	})

	t.Run("PAT without hostname in claims", func(t *testing.T) {
		pat := createMockPAT(t, `{}`)
		_, err := GetApiUrlFromPAT(pat)
		assert.Error(t, err)
	})

	t.Run("Invalid PAT", func(t *testing.T) {
		patTooManySegments := "snyk_test.12345678.payload.signature.extra"
		apiUrl, err := GetApiUrlFromPAT(patTooManySegments)
		assert.Error(t, err)
		assert.Equal(t, "", apiUrl)
	})
}

func createMockPAT(t *testing.T, payload string) string {
	t.Helper()

	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signature := "signature"
	return fmt.Sprintf("snyk_uat.12345678.%s.%s", encodedPayload, signature)
}
