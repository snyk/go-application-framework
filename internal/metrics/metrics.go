package metrics

// Recorder is satisfied by analytics.Analytics.
type Recorder interface {
	AddExtensionIntegerValue(key string, value int)
	AddExtensionStringValue(key string, value string)
	AddExtensionBoolValue(key string, value bool)
}
