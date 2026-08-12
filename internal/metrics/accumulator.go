package metrics

import "sync"

// Accumulator aggregates the metrics of repeated operations into one value per key, so that callers
// report under a fixed set of keys instead of namespacing every operation with a run identifier.
// A key must use the same aggregation throughout.
//
// A Recorder keeps only the last value per key, so every update writes the running aggregate
// through and there is nothing to flush. Two Accumulators sharing a key on one Recorder overwrite
// each other rather than aggregating, so operations reporting under one key must share one.
//
// An Accumulator is safe for concurrent use.
type Accumulator struct {
	mu       sync.Mutex
	recorder Recorder
	ints     map[string]int
}

// NewAccumulator returns an Accumulator writing through to recorder. A nil recorder discards
// everything; use Recording to skip obtaining values that are expensive to compute.
func NewAccumulator(recorder Recorder) *Accumulator {
	return &Accumulator{
		recorder: recorder,
		ints:     make(map[string]int),
	}
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

	a.mu.Lock()
	defer a.mu.Unlock()

	a.ints[key] += delta
	a.recorder.AddExtensionIntegerValue(key, a.ints[key])
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

	a.mu.Lock()
	defer a.mu.Unlock()

	if current, recorded := a.ints[key]; recorded && current >= value {
		return
	}

	a.ints[key] = value
	a.recorder.AddExtensionIntegerValue(key, value)
}
