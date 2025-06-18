package auth

import (
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
