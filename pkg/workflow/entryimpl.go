package workflow

import "sync"

// EntryImpl is the default implementation of the Entry interface.
type EntryImpl struct {
	// mu guards visible. The other fields are set once when the entry is created and do not change afterwards.
	mu             sync.RWMutex
	visible        bool
	expectedConfig ConfigurationOptions
	entryPoint     Callback
}

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
