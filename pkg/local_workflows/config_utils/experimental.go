package config_utils

import (
	"strings"

	"github.com/spf13/pflag"

	"github.com/snyk/go-application-framework/pkg/configuration"
)

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
