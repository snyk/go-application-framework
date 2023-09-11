package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_IsFedramp(t *testing.T) {
	assert.True(t, IsFedramp("https://api.fedramp.snykgov.io/something/else"))
	assert.True(t, IsFedramp("https://snykgov.io"))
	assert.False(t, IsFedramp("https://api.snyk.io/"))
}
