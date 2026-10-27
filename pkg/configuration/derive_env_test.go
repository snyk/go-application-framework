package configuration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Derive_EnvironmentAppliesExceptForBlockedKeys(t *testing.T) {
	t.Setenv("SNYK_TOKEN_FOR_TEST", "secret-from-env")
	t.Setenv("SNYK_ALIAS_FOR_TEST", "alias-secret-from-env")
	t.Setenv("SNYK_PROCESS_SETTING", "from-env")
	t.Setenv("OTHER_SETTING", "not-a-supported-key")

	newBase := func(opts ...Opts) Configuration {
		opts = append(opts, WithPinnedFile(filepath.Join(t.TempDir(), "base.json")))
		base := NewWithOpts(opts...)
		base.AddAlternativeKeys("snyk_token_for_test", []string{"snyk_alias_for_test"})
		return base
	}
	derive := func(base Configuration, blocked ...string) Configuration {
		derived, err := Derive(base, WithPinnedFile(filepath.Join(t.TempDir(), "derived.json")), WithEnvironmentBlockedFor(blocked...))
		require.NoError(t, err)
		return derived
	}

	t.Run("blocked keys and their alternatives do not read the environment, other keys do", func(t *testing.T) {
		base := newBase(WithSupportedEnvVarPrefixes("snyk_"))
		assert.Equal(t, "secret-from-env", base.GetString("snyk_token_for_test"))
		assert.Equal(t, "from-env", base.GetString("snyk_process_setting"))

		derived := derive(base, "snyk_token_for_test")

		assert.Equal(t, "from-env", derived.GetString("snyk_process_setting"), "settings of the process apply to the derived configuration too")
		assert.Empty(t, derived.GetString("snyk_token_for_test"), "a blocked key never reads the environment")
		assert.Empty(t, derived.GetString("snyk_alias_for_test"), "nor does an alternative key of a blocked key")
		assert.Empty(t, derived.GetAllKeysThatContainValues("snyk_token_for_test"))
		assert.Equal(t, []string{"snyk_process_setting"}, derived.GetAllKeysThatContainValues("snyk_process_setting"))

		clone := derived.Clone()
		assert.Equal(t, "from-env", clone.GetString("snyk_process_setting"), "the clone an invocation works on keeps the rule")
		assert.Empty(t, clone.GetString("snyk_token_for_test"))
		assert.Empty(t, clone.GetString("snyk_alias_for_test"))
		assert.Equal(t, EnvVarKeyType, clone.GetKeyType("snyk_token_for_test"), "the key is still known as an environment key")
	})

	t.Run("without blocked keys the derived configuration reads the whole environment", func(t *testing.T) {
		base := newBase(WithSupportedEnvVarPrefixes("snyk_"))
		derived := derive(base)
		assert.Equal(t, "secret-from-env", derived.GetString("snyk_token_for_test"))
	})

	t.Run("blocked keys are matched case-insensitively", func(t *testing.T) {
		base := newBase(WithSupportedEnvVarPrefixes("snyk_"))
		derived := derive(base, "SNYK_TOKEN_FOR_TEST")
		assert.Empty(t, derived.GetString("snyk_alias_for_test"))
		assert.Empty(t, derived.GetString("snyk_token_for_test"))
	})

	t.Run("an automatic environment applies to everything but blocked keys", func(t *testing.T) {
		base := newBase(WithAutomaticEnv())
		assert.Equal(t, "not-a-supported-key", base.GetString("other_setting"))
		assert.Equal(t, "secret-from-env", base.GetString("snyk_token_for_test"))

		derived := derive(base, "snyk_token_for_test")
		assert.Equal(t, "not-a-supported-key", derived.GetString("other_setting"))
		assert.Empty(t, derived.GetString("snyk_token_for_test"))
		assert.Empty(t, derived.GetString("snyk_alias_for_test"))
	})

	t.Run("a value that is set explicitly wins over the environment", func(t *testing.T) {
		base := newBase(WithSupportedEnvVarPrefixes("snyk_"))
		derived := derive(base, "snyk_token_for_test")
		derived.Set("snyk_process_setting", "set")
		assert.Equal(t, "set", derived.GetString("snyk_process_setting"))
	})

	t.Run("a persisted value is stored under the same name as the base would use", func(t *testing.T) {
		dir := t.TempDir()
		base := NewWithOpts(WithPinnedFile(filepath.Join(dir, "base.json")), WithSupportedEnvVarPrefixes("snyk_"))
		base.AddAlternativeKeys("token", []string{"snyk_derive_token", "stored_token"})
		base.PersistInStorage("snyk_derive_token")
		base.PersistInStorage("stored_token")

		derived, err := Derive(base, WithPinnedFile(filepath.Join(dir, "derived.json")))
		require.NoError(t, err)

		base.Set("snyk_derive_token", "value")
		derived.Set("snyk_derive_token", "value")
		baseFile, err := os.ReadFile(filepath.Join(dir, "base.json"))
		require.NoError(t, err)
		derivedFile, err := os.ReadFile(filepath.Join(dir, "derived.json"))
		require.NoError(t, err)
		assert.JSONEq(t, string(baseFile), string(derivedFile))
	})
}
