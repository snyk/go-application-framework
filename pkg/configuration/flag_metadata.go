package configuration

import "github.com/spf13/pflag"

// FlagMetadata provides read access to pflag.Flag.Annotations indexed during AddFlagSet.
// extendedViper implements this interface after flags are added via AddFlagSet.
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

// GetFlagAnnotation returns the first annotation value for the given flag name and annotation key.
func (ev *extendedViper) GetFlagAnnotation(name, annotation string) (string, bool) {
	ev.mutex.RLock()
	defer ev.mutex.RUnlock()

	f := ev.lookupFlag(name)
	if f == nil {
		return "", false
	}

	vals, ok := f.Annotations[annotation]
	if !ok || len(vals) == 0 {
		return "", false
	}

	return vals[0], true
}

// FlagsByAnnotation returns all flag names whose given annotation matches value.
func (ev *extendedViper) FlagsByAnnotation(annotation, value string) []string {
	ev.mutex.RLock()
	defer ev.mutex.RUnlock()

	var result []string
	for _, fs := range ev.flagsets {
		fs.VisitAll(func(f *pflag.Flag) {
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
	}

	return result
}

// FlagNameByAnnotation returns the first flag name whose annotation equals value.
func (ev *extendedViper) FlagNameByAnnotation(annotation, value string) (string, bool) {
	ev.mutex.RLock()
	defer ev.mutex.RUnlock()

	for _, fs := range ev.flagsets {
		var found string
		fs.VisitAll(func(f *pflag.Flag) {
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
	}

	return "", false
}

// GetFlagType returns the pflag type string for the named flag.
func (ev *extendedViper) GetFlagType(name string) string {
	ev.mutex.RLock()
	defer ev.mutex.RUnlock()

	f := ev.lookupFlag(name)
	if f == nil {
		return ""
	}

	return f.Value.Type()
}

// GetFlagUsage returns the usage string for the named flag.
func (ev *extendedViper) GetFlagUsage(name string) string {
	ev.mutex.RLock()
	defer ev.mutex.RUnlock()

	f := ev.lookupFlag(name)
	if f == nil {
		return ""
	}

	return f.Usage
}

// lookupFlag searches all registered flagsets for the flag with the given name.
// Caller must hold at least a read lock.
func (ev *extendedViper) lookupFlag(name string) *pflag.Flag {
	for _, fs := range ev.flagsets {
		if f := fs.Lookup(name); f != nil {
			return f
		}
	}

	return nil
}
