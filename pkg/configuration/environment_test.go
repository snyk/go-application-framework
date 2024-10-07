package configuration

import (
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/subosito/gotenv"
)

var pathListSep = string(os.PathListSeparator)

func TestUpdatePathWithDefaults(t *testing.T) {

	t.Run("add to path from environment", func(t *testing.T) {
		pathFromEnv := "a"
		t.Setenv("PATH", pathFromEnv)

		UpdatePath("b")

		assert.Contains(t, os.Getenv("PATH"), pathListSep+"b")
	})

	t.Run("add to path from environment only once", func(t *testing.T) {
		pathFromEnv := "a"
		t.Setenv("PATH", pathFromEnv)

		UpdatePath("b")
		UpdatePath("b")

		assert.Equal(t, pathFromEnv+pathListSep+"b", os.Getenv("PATH"))
	})

	t.Run("add to path from environment only if not blank", func(t *testing.T) {
		pathFromEnv := "a"
		t.Setenv("PATH", pathFromEnv)

		UpdatePath("")

		assert.Equal(t, pathFromEnv, os.Getenv("PATH"))
	})
}

func TestSetParsedVariablesToEnv(t *testing.T) {
	additionalEnv := gotenv.Env{}

	t.Run("add to path from environment", func(t *testing.T) {
		t.Setenv("a", "new")
		t.Setenv("PATH", "abc")
		additionalEnv["PATH"] = "b"
		additionalEnv["a"] = "old"

		SetParsedVariablesToEnv(additionalEnv)

		assert.Equal(t, "abc"+pathListSep+"b", os.Getenv("PATH"))
	})

	t.Run("add variables to env if not existent", func(t *testing.T) {
		newEnvVar := uuid.New().String()
		additionalEnv[newEnvVar] = "abc"

		SetParsedVariablesToEnv(additionalEnv)

		assert.Equal(t, "abc", os.Getenv(newEnvVar))
	})

	t.Run("skip variables if existent", func(t *testing.T) {
		newEnvVar := uuid.New().String()
		t.Setenv(newEnvVar, "old")
		additionalEnv[newEnvVar] = "abc"

		SetParsedVariablesToEnv(additionalEnv)

		assert.Equal(t, "old", os.Getenv(newEnvVar))
	})
}
