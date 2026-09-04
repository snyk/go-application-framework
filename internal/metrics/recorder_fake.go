package metrics

import "sync"

// RecorderFake is a simple in-memory Recorder for use in tests.
// Like the production recorder it may be written to concurrently, so its values are mutex guarded.
type RecorderFake struct {
	mu           sync.Mutex
	IntValues    map[string]int
	StringValues map[string]string
	BoolValues   map[string]bool
}

// NewRecorderFake returns an initialized recorder.
func NewRecorderFake() *RecorderFake {
	return &RecorderFake{
		IntValues:    make(map[string]int),
		StringValues: make(map[string]string),
		BoolValues:   make(map[string]bool),
	}
}

func (r *RecorderFake) AddExtensionIntegerValue(key string, value int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.IntValues[key] = value
}

func (r *RecorderFake) AddExtensionStringValue(key string, value string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.StringValues[key] = value
}

func (r *RecorderFake) AddExtensionBoolValue(key string, value bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.BoolValues[key] = value
}
