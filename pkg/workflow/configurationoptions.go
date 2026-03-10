package workflow

import (
	"sync"

	"github.com/spf13/pflag"
)

// FlagMetadata provides read access to pflag.Flag.Annotations on registered flagsets.
type FlagMetadata interface {
	// GetFlagAnnotation returns the first value for the given annotation on the named flag.
	// Returns ("", false) when the flag or annotation does not exist.
	GetFlagAnnotation(name, annotation string) (string, bool)

	// FlagsByAnnotation returns all flag names whose annotation matches the given value.
	FlagsByAnnotation(annotation, value string) []string

	// FlagNameByAnnotation returns the flag name whose annotation equals value.
	// Useful for reverse-lookup: given a remote key, find the canonical flag name.
	// Returns ("", false) when no flag matches.
	FlagNameByAnnotation(annotation, value string) (string, bool)

	// GetFlagType returns the pflag type string (e.g. "bool", "string", "int") for the named flag.
	// Returns "" when the flag does not exist.
	GetFlagType(name string) string

	// GetFlagUsage returns the usage string for the named flag.
	// Returns "" when the flag does not exist.
	GetFlagUsage(name string) string
}

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
	if f == nil || f.Value == nil {
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

// ConfigurationOptionsStore aggregates multiple ConfigurationOptions and implements FlagMetadata
// by delegating to each registered option. Safe for concurrent use.
type ConfigurationOptionsStore struct {
	mu   sync.RWMutex
	opts []ConfigurationOptions
}

// NewConfigurationOptionsStore creates a ConfigurationOptionsStore pre-loaded with the given ConfigurationOptions.
func NewConfigurationOptionsStore(opts ...ConfigurationOptions) *ConfigurationOptionsStore {
	return &ConfigurationOptionsStore{opts: opts}
}

// Add registers an additional ConfigurationOptions for annotation lookup.
func (s *ConfigurationOptionsStore) Add(opt ConfigurationOptions) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opts = append(s.opts, opt)
}

// Last-registered option wins, consistent with Viper's BindPFlags overwrite semantics.
func (s *ConfigurationOptionsStore) GetFlagAnnotation(name, annotation string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := len(s.opts) - 1; i >= 0; i-- {
		if val, found := s.opts[i].GetFlagAnnotation(name, annotation); found {
			return val, true
		}
	}
	return "", false
}

func (s *ConfigurationOptionsStore) FlagsByAnnotation(annotation, value string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	seen := make(map[string]struct{})
	var result []string
	for _, opt := range s.opts {
		for _, name := range opt.FlagsByAnnotation(annotation, value) {
			if _, dup := seen[name]; !dup {
				seen[name] = struct{}{}
				result = append(result, name)
			}
		}
	}
	return result
}

// Last-registered option wins, consistent with Viper's BindPFlags overwrite semantics.
func (s *ConfigurationOptionsStore) FlagNameByAnnotation(annotation, value string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := len(s.opts) - 1; i >= 0; i-- {
		if name, found := s.opts[i].FlagNameByAnnotation(annotation, value); found {
			return name, true
		}
	}
	return "", false
}

// Last-registered option wins, consistent with Viper's BindPFlags overwrite semantics.
func (s *ConfigurationOptionsStore) GetFlagType(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := len(s.opts) - 1; i >= 0; i-- {
		if t := s.opts[i].GetFlagType(name); t != "" {
			return t
		}
	}
	return ""
}

// Last-registered option wins, consistent with Viper's BindPFlags overwrite semantics.
func (s *ConfigurationOptionsStore) GetFlagUsage(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := len(s.opts) - 1; i >= 0; i-- {
		if u := s.opts[i].GetFlagUsage(name); u != "" {
			return u
		}
	}
	return ""
}
