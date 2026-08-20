package metrics

import "sync"

// accumulated is shared by all Accumulators.
var (
	accumulatedMu sync.Mutex
	accumulated   = map[string]int{}
)

// Accumulator safely aggregates repeated operations by key.
type Accumulator struct {
	recorder Recorder
}

// NewAccumulator writes shared aggregates to recorder; a nil recorder discards values.
func NewAccumulator(recorder Recorder) *Accumulator {
	return &Accumulator{recorder: recorder}
}

// ResetAccumulated clears shared values between tests.
func ResetAccumulated() {
	accumulatedMu.Lock()
	defer accumulatedMu.Unlock()

	accumulated = map[string]int{}
}

// IsRecording reports whether values written to this Accumulator reach a Recorder.
func (a *Accumulator) IsRecording() bool {
	return a != nil && a.recorder != nil
}

// AddToSum adds delta to the running sum recorded under key.
func (a *Accumulator) AddToSum(key string, delta int) {
	if !a.IsRecording() {
		return
	}

	accumulatedMu.Lock()
	defer accumulatedMu.Unlock()

	accumulated[key] += delta
	a.recorder.AddExtensionIntegerValue(key, accumulated[key])
}

// RecordBool writes value without aggregation.
func (a *Accumulator) RecordBool(key string, value bool) {
	if !a.IsRecording() {
		return
	}

	a.recorder.AddExtensionBoolValue(key, value)
}

// KeepMaximum records the largest value seen under key.
func (a *Accumulator) KeepMaximum(key string, value int) {
	if !a.IsRecording() {
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
