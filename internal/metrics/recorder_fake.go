package metrics

// RecorderFake is a simple in-memory Recorder for use in tests.
type RecorderFake struct {
	IntValues    map[string]int
	StringValues map[string]string
	BoolValues   map[string]bool
}

func (r *RecorderFake) AddExtensionIntegerValue(key string, value int) {
	if r.IntValues == nil {
		r.IntValues = make(map[string]int)
	}
	r.IntValues[key] = value
}

func (r *RecorderFake) AddExtensionStringValue(key string, value string) {
	if r.StringValues == nil {
		r.StringValues = make(map[string]string)
	}
	r.StringValues[key] = value
}

func (r *RecorderFake) AddExtensionBoolValue(key string, value bool) {
	if r.BoolValues == nil {
		r.BoolValues = make(map[string]bool)
	}
	r.BoolValues[key] = value
}
