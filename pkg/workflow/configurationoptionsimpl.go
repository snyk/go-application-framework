package workflow

import (
	"github.com/spf13/pflag"
)

type ConfigurationOptionsImpl struct {
	flagset pflag.FlagSet
}

func ConfigurationOptionsFromFlagset(flagset *pflag.FlagSet) ConfigurationOptions {
	result := ConfigurationOptionsImpl{
		flagset: *flagset,
	}
	return result
}

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
