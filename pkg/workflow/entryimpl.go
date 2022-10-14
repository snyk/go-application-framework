package workflow

type EntryImpl struct {
	visible        bool
	expectedConfig ConfigurationOptions
	entryPoint     Callback
}

func (e *EntryImpl) GetEntryPoint() Callback {
	return e.entryPoint
}

func (e *EntryImpl) GetConfigurationOptions() ConfigurationOptions {
	return e.expectedConfig
}

func (e *EntryImpl) IsVisible() bool {
	return e.visible
}

func (e *EntryImpl) SetVisibility(visible bool) {
	e.visible = visible
}
