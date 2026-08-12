package metrics

import "sync"

// accumulated is shared by every Accumulator, so two of them reporting under one key add up
// instead of overwriting each other in a Recorder, which keeps only the last value per key.
var (
	accumulatedMu sync.Mutex
	accumulated   = map[string]int{}
)

// Accumulator aggregates repeated operations into one running value per key, so callers report
// under a fixed set of keys instead of namespacing every operation. Safe for concurrent use.
type Accumulator struct {
	recorder Recorder
}

// NewAccumulator returns an Accumulator writing through to recorder; a nil recorder discards
// everything. It continues the shared aggregate rather than starting one of its own.
func NewAccumulator(recorder Recorder) *Accumulator {
	return &Accumulator{recorder: recorder}
}

// ResetAccumulated discards every accumulated value. It exists for tests, which assert the values a
// single Recorder saw and would otherwise observe the aggregate of preceding tests.
func ResetAccumulated() {
	accumulatedMu.Lock()
	defer accumulatedMu.Unlock()

	accumulated = map[string]int{}
}

// Recording reports whether values written to this Accumulator reach a Recorder.
func (a *Accumulator) Recording() bool {
	return a != nil && a.recorder != nil
}

// AddToSum adds delta to the running sum recorded under key.
func (a *Accumulator) AddToSum(key string, delta int) {
	if !a.Recording() {
		return
	}

	accumulatedMu.Lock()
	defer accumulatedMu.Unlock()

	accumulated[key] += delta
	a.recorder.AddExtensionIntegerValue(key, accumulated[key])
}

// RecordBool records value under key, overwriting whatever was recorded for it before. Unlike
// AddToSum or KeepMaximum, a bool is not aggregated: callers reporting a fact that does not change
// between calls (e.g. whether a feature flag applied to the run) simply see it written through.
func (a *Accumulator) RecordBool(key string, value bool) {
	if !a.Recording() {
		return
	}

	a.recorder.AddExtensionBoolValue(key, value)
}

// KeepMaximum records value under key unless a larger value was recorded for it before. It keeps an
// outlier visible where a sum would hide it, e.g. the slowest of many operations.
func (a *Accumulator) KeepMaximum(key string, value int) {
	if !a.Recording() {
		return
	}

	accumulatedMu.Lock()
	defer accumulatedMu.Unlock()

	if current, recorded := accumulated[key]; recorded && current >= value {
		return
	}

	accumulated[key] = value
	a.recorder.AddExtensionIntegerValue(key, value)
}
