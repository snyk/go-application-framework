package config_utils

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

func TestIsExperimental(t *testing.T) {
	tests := []struct {
		name           string
		setupFlags     func() *pflag.FlagSet
		expectedResult bool
	}{
		{
			name: "returns false when experimental flag does not exist",
			setupFlags: func() *pflag.FlagSet {
				flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
				flags.String("other-flag", "", "some other flag")
				return flags
			},
			expectedResult: false,
		},
		{
			name: "returns true when experimental flag exists and is not deprecated",
			setupFlags: func() *pflag.FlagSet {
				flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
				return MarkAsExperimental(flags)
			},
			expectedResult: true,
		},
		{
			name: "returns false when experimental flag usage contains 'deprecated' (case insensitive)",
			setupFlags: func() *pflag.FlagSet {
				flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
				flags.Bool(configuration.FLAG_EXPERIMENTAL, false, "This is DEPRECATED and should not be used")
				return flags
			},
			expectedResult: false,
		},
		{
			name: "returns false when experimental flag deprecated field is set",
			setupFlags: func() *pflag.FlagSet {
				flags := MarkAsExperimental(pflag.NewFlagSet("test", pflag.ContinueOnError))
				flags.MarkDeprecated(configuration.FLAG_EXPERIMENTAL, "use new-flag instead")
				return flags
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags := tt.setupFlags()
			result := IsExperimental(flags)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}

func TestMarkAsExperimental(t *testing.T) {
	t.Run("makes non-experimental flagset experimental", func(t *testing.T) {
		original := pflag.NewFlagSet("test", pflag.ContinueOnError)
		original.String("existing-flag", "", "existing flag")

		result := MarkAsExperimental(original)

		// Should make the flagset experimental
		assert.True(t, IsExperimental(result), "flagset should be experimental after marking")
	})

	t.Run("returns different flagset instance", func(t *testing.T) {
		original := pflag.NewFlagSet("test", pflag.ContinueOnError)

		result := MarkAsExperimental(original)

		// Should return a different instance
		assert.NotSame(t, original, result, "should return a new flagset instance")

		// Original should not be experimental, result should be
		assert.False(t, IsExperimental(original), "original flagset should not be experimental")
		assert.True(t, IsExperimental(result), "result flagset should be experimental")
	})

	t.Run("makes empty flagset experimental", func(t *testing.T) {
		original := pflag.NewFlagSet("empty", pflag.ContinueOnError)

		result := MarkAsExperimental(original)

		// Should make empty flagset experimental
		assert.True(t, IsExperimental(result), "empty flagset should be experimental after marking")
	})

	t.Run("preserves existing experimental flag", func(t *testing.T) {
		original := pflag.NewFlagSet("test", pflag.ContinueOnError)
		original.Bool(configuration.FLAG_EXPERIMENTAL, true, "old usage")

		result := MarkAsExperimental(original)

		// Should remain experimental
		assert.True(t, IsExperimental(result), "should remain experimental")
	})

	t.Run("works with both new and existing experimental flags", func(t *testing.T) {
		// Test with flagset that doesn't have experimental flag
		original1 := pflag.NewFlagSet("test1", pflag.ContinueOnError)
		original1.String("other-flag", "", "some other flag")

		result1 := MarkAsExperimental(original1)

		// Should be experimental after adding flag
		assert.True(t, IsExperimental(result1), "should be experimental after adding flag")

		// Test with flagset that already has experimental flag (reuse result1)
		result2 := MarkAsExperimental(result1)

		// Should remain experimental
		assert.True(t, IsExperimental(result2), "should remain experimental")
	})
}
