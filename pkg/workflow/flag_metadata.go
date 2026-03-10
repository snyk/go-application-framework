package workflow

import (
	"sync"
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

// FlagMetadataStore aggregates multiple ConfigurationOptions and implements FlagMetadata
// by delegating to each registered option. Safe for concurrent use.
type FlagMetadataStore struct {
	mu   sync.RWMutex
	opts []ConfigurationOptions
}

// NewFlagMetadata creates a FlagMetadataStore pre-loaded with the given ConfigurationOptions.
func NewFlagMetadata(opts ...ConfigurationOptions) *FlagMetadataStore {
	return &FlagMetadataStore{opts: opts}
}

// Add registers an additional ConfigurationOptions for annotation lookup.
func (s *FlagMetadataStore) Add(opt ConfigurationOptions) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.opts = append(s.opts, opt)
}

func (s *FlagMetadataStore) GetFlagAnnotation(name, annotation string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, opt := range s.opts {
		if val, found := opt.GetFlagAnnotation(name, annotation); found {
			return val, true
		}
	}
	return "", false
}

func (s *FlagMetadataStore) FlagsByAnnotation(annotation, value string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []string
	for _, opt := range s.opts {
		result = append(result, opt.FlagsByAnnotation(annotation, value)...)
	}
	return result
}

func (s *FlagMetadataStore) FlagNameByAnnotation(annotation, value string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, opt := range s.opts {
		if name, found := opt.FlagNameByAnnotation(annotation, value); found {
			return name, true
		}
	}
	return "", false
}

func (s *FlagMetadataStore) GetFlagType(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, opt := range s.opts {
		if t := opt.GetFlagType(name); t != "" {
			return t
		}
	}
	return ""
}

func (s *FlagMetadataStore) GetFlagUsage(name string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, opt := range s.opts {
		if u := opt.GetFlagUsage(name); u != "" {
			return u
		}
	}
	return ""
}
