package config_utils

import (
	"strings"

	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

// IsExperimental checks if the flagset requires the experimental flag
func IsExperimental(flags *pflag.FlagSet) bool {
	result := false

	// if the experimental flag exists, it's an experimental command
	if tmp := flags.Lookup(configuration.FLAG_EXPERIMENTAL); tmp != nil {
		result = true

		// if the experimental flag is deprecated, it'll be ignored
		if strings.Contains(strings.ToLower(tmp.Usage), "deprecated") ||
			len(tmp.Deprecated) > 0 {
			result = false
		}
	}

	return result
}

// MarkAsExperimental ensures that the flagset requires the experimental flag
func MarkAsExperimental(flags *pflag.FlagSet) *pflag.FlagSet {
	if flags == nil {
		return nil
	}

	result := *flags
	if result.Lookup(configuration.FLAG_EXPERIMENTAL) == nil {
		result.Bool(configuration.FLAG_EXPERIMENTAL, false, "enable experimental command")
	}
	return &result
}

// MarkAsUsedToBeExperimental ensures that the flagset accepts the experimental flag but marks it as deprecated
func MarkAsUsedToBeExperimental(flags *pflag.FlagSet) *pflag.FlagSet {
	if flags == nil {
		return nil
	}

	result := *flags
	tmp := result.Lookup(configuration.FLAG_EXPERIMENTAL)
	if tmp == nil {
		result.Bool(configuration.FLAG_EXPERIMENTAL, false, "enable experimental command")
		tmp = result.Lookup(configuration.FLAG_EXPERIMENTAL)
	}

	tmp.Usage = tmp.Usage + " (deprecated)"
	return &result
}
