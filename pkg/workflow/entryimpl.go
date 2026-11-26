package workflow

import (
	"fmt"
	"maps"
	"sync"
)

// EntryImpl is the default implementation of the Entry interface and of EntryWithMetadata.
type EntryImpl struct {
	// mu guards visible and metadata. The other fields are set once when the entry is created and do not change afterwards.
	mu             sync.RWMutex
	visible        bool
	metadata       map[string]any
	expectedConfig ConfigurationOptions
	entryPoint     Callback
}

var _ EntryWithMetadata = (*EntryImpl)(nil)

// GetEntryPoint returns the entry point callback for the workflow entry.
func (e *EntryImpl) GetEntryPoint() Callback {
	return e.entryPoint
}

// GetConfigurationOptions returns the configuration options for the workflow entry.
func (e *EntryImpl) GetConfigurationOptions() ConfigurationOptions {
	return e.expectedConfig
}

// IsVisible returns true if the workflow entry is visible.
func (e *EntryImpl) IsVisible() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.visible
}

// SetVisibility sets the visibility of the workflow entry.
func (e *EntryImpl) SetVisibility(visible bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.visible = visible
}

// SetMetadata stores value under key. A key can be set only once; setting it again returns an error and keeps the
// first value.
func (e *EntryImpl) SetMetadata(key string, value any) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, exists := e.metadata[key]; exists {
		return fmt.Errorf("metadata key %q is already set", key)
	}
	if e.metadata == nil {
		e.metadata = make(map[string]any)
	}
	e.metadata[key] = value
	return nil
}

// Metadata returns a shallow copy of the metadata of the workflow entry.
func (e *EntryImpl) Metadata() map[string]any {
	e.mu.RLock()
	defer e.mu.RUnlock()
	result := make(map[string]any, len(e.metadata))
	maps.Copy(result, e.metadata)
	return result
}
