package workflow

import (
	"github.com/spf13/pflag"
)

// ConfigurationOptionsImpl is a wrapper around a pflag.FlagSet.
type ConfigurationOptionsImpl struct {
	flagset pflag.FlagSet
}

// ConfigurationOptionsFromFlagset implements the ConfigurationOptions interface.
// It returns a ConfigurationOptionsImpl instance that wraps the given pflag.FlagSet.
func ConfigurationOptionsFromFlagset(flagset *pflag.FlagSet) ConfigurationOptions {
	result := ConfigurationOptionsImpl{
		flagset: *flagset,
	}
	return result
}

// FlagsetFromConfigurationOptions extracts the pflag.FlagSet from a ConfigurationOptions implementation.
func FlagsetFromConfigurationOptions(param ConfigurationOptions) *pflag.FlagSet {
	var result *pflag.FlagSet
	if impl, ok := param.(ConfigurationOptionsImpl); ok {
		result = &impl.flagset
	}
	return result
}

func ConfigurationOptionsFromJson(bytes []byte) ConfigurationOptions {
	return nil
}

func JsonFromConfigurationOptions(param ConfigurationOptions) []byte {
	return nil
}
