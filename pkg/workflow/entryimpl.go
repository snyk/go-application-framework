package workflow

// EntryImpl is the default implementation of the Entry interface.
type EntryImpl struct {
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
	return e.visible
}

// SetVisibility sets the visibility of the workflow entry.
func (e *EntryImpl) SetVisibility(visible bool) {
	e.visible = visible
}
