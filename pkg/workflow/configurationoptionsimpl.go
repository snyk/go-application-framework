package workflow

import (
	"github.com/spf13/pflag"
)

// ConfigurationOptionsImpl is a wrapper around a pflag.FlagSet.
type ConfigurationOptionsImpl struct {
	flagset pflag.FlagSet
}

// ConfigurationOptionsFromFlagset creates a ConfigurationOptions backed by the given pflag.FlagSet.
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

// FlagMetadata implementation for ConfigurationOptionsImpl.

func (c ConfigurationOptionsImpl) GetFlagAnnotation(name, annotation string) (string, bool) {
	f := c.flagset.Lookup(name)
	if f == nil {
		return "", false
	}
	vals, ok := f.Annotations[annotation]
	if !ok || len(vals) == 0 {
		return "", false
	}
	return vals[0], true
}

func (c ConfigurationOptionsImpl) FlagsByAnnotation(annotation, value string) []string {
	var result []string
	c.flagset.VisitAll(func(f *pflag.Flag) {
		vals, ok := f.Annotations[annotation]
		if !ok {
			return
		}
		for _, v := range vals {
			if v == value {
				result = append(result, f.Name)
				return
			}
		}
	})
	return result
}

func (c ConfigurationOptionsImpl) FlagNameByAnnotation(annotation, value string) (string, bool) {
	var found string
	c.flagset.VisitAll(func(f *pflag.Flag) {
		if found != "" {
			return
		}
		vals, ok := f.Annotations[annotation]
		if !ok {
			return
		}
		for _, v := range vals {
			if v == value {
				found = f.Name
				return
			}
		}
	})
	if found != "" {
		return found, true
	}
	return "", false
}

func (c ConfigurationOptionsImpl) GetFlagType(name string) string {
	f := c.flagset.Lookup(name)
	if f == nil {
		return ""
	}
	return f.Value.Type()
}

func (c ConfigurationOptionsImpl) GetFlagUsage(name string) string {
	f := c.flagset.Lookup(name)
	if f == nil {
		return ""
	}
	return f.Usage
}
