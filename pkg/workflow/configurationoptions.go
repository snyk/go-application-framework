package workflow

import (
	"log"
	"strings"

	"github.com/spf13/pflag"
)

// ConfigurationOptionsImpl is a wrapper around a pflag.FlagSet.
// The flagset is stored as a pointer to avoid copying the embedded sync.Mutex.
type ConfigurationOptionsImpl struct {
	flagset *pflag.FlagSet
}

// ConfigurationOptionsFromFlagset creates a ConfigurationOptions backed by the given pflag.FlagSet.
// Returns nil when flagset is nil.
// Logs a warning if any flag name contains a colon, which could collide with the prefix key delimiter.
func ConfigurationOptionsFromFlagset(flagset *pflag.FlagSet) ConfigurationOptions {
	if flagset == nil {
		return nil
	}
	flagset.VisitAll(func(f *pflag.Flag) {
		if strings.Contains(f.Name, ":") {
			log.Printf("WARNING: flag name %q contains a colon, which may collide with the internal key delimiter", f.Name)
		}
	})
	return ConfigurationOptionsImpl{flagset: flagset}
}

// FlagsetFromConfigurationOptions extracts the pflag.FlagSet from a ConfigurationOptions implementation.
func FlagsetFromConfigurationOptions(param ConfigurationOptions) *pflag.FlagSet {
	if impl, ok := param.(ConfigurationOptionsImpl); ok {
		return impl.flagset
	}
	return nil
}

func ConfigurationOptionsFromJson(bytes []byte) ConfigurationOptions {
	return nil
}

func JsonFromConfigurationOptions(param ConfigurationOptions) []byte {
	return nil
}

func (c ConfigurationOptionsImpl) GetConfigurationOptionAnnotation(name, annotation string) (string, bool) {
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

func (c ConfigurationOptionsImpl) ConfigurationOptionsByAnnotation(annotation, value string) []string {
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

func (c ConfigurationOptionsImpl) ConfigurationOptionNameByAnnotation(annotation, value string) (string, bool) {
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

func (c ConfigurationOptionsImpl) GetConfigurationOptionType(name string) string {
	f := c.flagset.Lookup(name)
	if f == nil || f.Value == nil {
		return ""
	}
	return f.Value.Type()
}

func (c ConfigurationOptionsImpl) GetConfigurationOptionUsage(name string) string {
	f := c.flagset.Lookup(name)
	if f == nil {
		return ""
	}
	return f.Usage
}
