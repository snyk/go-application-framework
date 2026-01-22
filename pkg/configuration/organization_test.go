package configuration

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetUserPreferredOrganization_ReturnsSetValue(t *testing.T) {
	config := NewInMemory()
	expectedOrg := "00000000-0000-0000-0000-000000000001"
	config.Set(userPreferredOrganization, expectedOrg)

	org, err := GetUserPreferredOrganization(config)

	require.NoError(t, err)
	assert.Equal(t, expectedOrg, org)
}

func Test_GetUserPreferredOrganization_ErrorsWhenEmpty(t *testing.T) {
	config := NewInMemory()
	config.Set(userPreferredOrganization, "")

	org, err := GetUserPreferredOrganization(config)

	assert.ErrorIs(t, err, ErrNoUserPreferredOrganization)
	assert.Empty(t, org)
}

func Test_GetUserPreferredOrganization_ErrorsWhenNotSet(t *testing.T) {
	config := NewInMemory()

	org, err := GetUserPreferredOrganization(config)

	assert.Error(t, err)
	assert.Empty(t, org)
}

func Test_IsUserPreferredOrganization_ReturnsTrueWhenMatch(t *testing.T) {
	config := NewInMemory()
	preferredOrg := "00000000-0000-0000-0000-000000000001"
	config.Set(userPreferredOrganization, preferredOrg)

	isPreferred, err := IsUserPreferredOrganization(config, preferredOrg)

	require.NoError(t, err)
	assert.True(t, isPreferred)
}

func Test_IsUserPreferredOrganization_ReturnsFalseWhenNoMatch(t *testing.T) {
	config := NewInMemory()
	preferredOrg := "00000000-0000-0000-0000-000000000001"
	otherOrg := "00000000-0000-0000-0000-000000000002"
	config.Set(userPreferredOrganization, preferredOrg)

	isPreferred, err := IsUserPreferredOrganization(config, otherOrg)

	require.NoError(t, err)
	assert.False(t, isPreferred)
}

func Test_IsUserPreferredOrganization_ErrorsWhenNoPreferredOrg(t *testing.T) {
	config := NewInMemory()

	isPreferred, err := IsUserPreferredOrganization(config, "some-org")

	assert.Error(t, err)
	assert.False(t, isPreferred)
}

func Test_RegisterUserPreferredOrganizationDefault_RegistersDefaultValue(t *testing.T) {
	config := NewInMemory()
	expectedOrg := "00000000-0000-0000-0000-000000000001"

	err := RegisterUserPreferredOrganizationDefault(config, ImmutableDefaultValueFunction(expectedOrg), nil)
	require.NoError(t, err)

	// The default value function should be called when getting the value
	org, err := GetUserPreferredOrganization(config)
	require.NoError(t, err)
	assert.Equal(t, expectedOrg, org)
}
