package subprocess

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleanEnv_StripsSnykCredentials(t *testing.T) {
	env := []string{
		"PATH=/usr/bin",
		"SNYK_TOKEN=token",
		"SNYK_OAUTH_TOKEN=oauth",
		"SNYK_CFG_API=api",
		"HOME=/home/user",
	}

	result := cleanEnv(env)

	assert.Equal(t, []string{"PATH=/usr/bin", "HOME=/home/user"}, result)
}

func TestCleanEnv_PrefixMatchIsCaseInsensitive(t *testing.T) {
	env := []string{
		"Snyk_Token=a",
		"snyk_token=b",
		"SNYK_token=c",
		"PATH=/bin",
	}

	result := cleanEnv(env)

	assert.Equal(t, []string{"PATH=/bin"}, result)
}

func TestCleanEnv_KeepsNonSnykPrefixLookalikes(t *testing.T) {
	env := []string{
		"PATH=/bin",
		"HOME=/home/user",
		"MY_SNYK_THING=1",
		"SNYKX=2",
		"SNYK=3",
		"XSNYK_TOKEN=4",
	}

	result := cleanEnv(env)

	assert.Equal(t, env, result)
}

func TestCleanEnv_DoesNotMutateInput(t *testing.T) {
	env := []string{
		"PATH=/bin",
		"SNYK_TOKEN=token",
		"Snyk_Cfg_Api=api",
		"HOME=/home/user",
	}
	before := make([]string, len(env))
	copy(before, env)

	_ = cleanEnv(env)

	assert.Equal(t, before, env)
}

func TestCleanEnv_ResultDoesNotAliasInput(t *testing.T) {
	t.Run("entries removed", func(t *testing.T) {
		env := []string{"PATH=/bin", "SNYK_TOKEN=token"}

		result := cleanEnv(env)
		require.Len(t, result, 1)
		result[0] = "CHANGED=1"

		assert.Equal(t, []string{"PATH=/bin", "SNYK_TOKEN=token"}, env)
	})

	t.Run("nothing removed", func(t *testing.T) {
		env := []string{"PATH=/bin", "HOME=/home/user"}

		result := cleanEnv(env)
		require.Len(t, result, 2)
		result[0] = "CHANGED=1"

		assert.Equal(t, []string{"PATH=/bin", "HOME=/home/user"}, env)
	})
}

func TestCleanEnv_PreservesOrderOfRemainingEntries(t *testing.T) {
	env := []string{
		"Z=1",
		"SNYK_TOKEN=a",
		"A=2",
		"SNYK_CFG_API=b",
		"M=3",
	}

	result := cleanEnv(env)

	assert.Equal(t, []string{"Z=1", "A=2", "M=3"}, result)
}

func TestCleanEnv_KeepsEntriesWithoutEquals(t *testing.T) {
	env := []string{
		"BARE",
		"SNYK_TOKEN=token",
		"",
	}

	result := cleanEnv(env)

	assert.Equal(t, []string{"BARE", ""}, result)
}

func TestCleanEnv_KeepsWindowsDriveEntries(t *testing.T) {
	env := []string{
		"=C:=C:\\work",
		"=D:=D:\\data",
		"SNYK_TOKEN=token",
	}

	result := cleanEnv(env)

	assert.Equal(t, []string{"=C:=C:\\work", "=D:=D:\\data"}, result)
}

func TestCleanEnv_RemovesEmptyValueEntries(t *testing.T) {
	env := []string{
		"SNYK_TOKEN=",
		"PATH=",
	}

	result := cleanEnv(env)

	assert.Equal(t, []string{"PATH="}, result)
}

func TestCleanEnv_ValueContainingEqualsIsStripped(t *testing.T) {
	env := []string{"SNYK_TOKEN=a=b=c", "PATH=/bin"}

	result := cleanEnv(env)

	assert.Equal(t, []string{"PATH=/bin"}, result)
}

func TestCleanEnv_NilAndEmptyInput(t *testing.T) {
	for name, env := range map[string][]string{
		"nil":   nil,
		"empty": {},
	} {
		t.Run(name, func(t *testing.T) {
			result := cleanEnv(env)

			require.NotNil(t, result)
			assert.Empty(t, result)
		})
	}
}

func TestCleanEnv_DoesNotTouchProcessEnvironment(t *testing.T) {
	t.Setenv("SNYK_TOKEN", "process-secret")

	result := cleanEnv(os.Environ())

	assert.NotContains(t, result, "SNYK_TOKEN=process-secret")
	assert.Equal(t, "process-secret", os.Getenv("SNYK_TOKEN"))
}
