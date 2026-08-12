package metrics_test

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/internal/metrics"
)

func TestAccumulator_AddToSum(t *testing.T) {
	t.Run("writes the running sum through on every update", func(t *testing.T) {
		recorder := &metrics.RecorderFake{}
		accumulator := metrics.NewAccumulator(recorder)

		accumulator.AddToSum("files", 2)
		assert.Equal(t, 2, recorder.IntValues["files"])

		accumulator.AddToSum("files", 3)
		assert.Equal(t, 5, recorder.IntValues["files"], "the recorder must hold the aggregate, not the last delta")
	})

	t.Run("keeps sums of different keys apart", func(t *testing.T) {
		recorder := &metrics.RecorderFake{}
		accumulator := metrics.NewAccumulator(recorder)

		accumulator.AddToSum("files", 2)
		accumulator.AddToSum("rules", 7)
		accumulator.AddToSum("files", 1)

		assert.Equal(t, map[string]int{"files": 3, "rules": 7}, recorder.IntValues)
	})

	t.Run("records a zero delta so the key is present", func(t *testing.T) {
		recorder := &metrics.RecorderFake{}

		metrics.NewAccumulator(recorder).AddToSum("files", 0)

		assert.Equal(t, map[string]int{"files": 0}, recorder.IntValues)
	})
}

func TestAccumulator_RecordBool(t *testing.T) {
	t.Run("writes the value through", func(t *testing.T) {
		recorder := &metrics.RecorderFake{}

		metrics.NewAccumulator(recorder).RecordBool("featureEnabled", true)

		assert.Equal(t, map[string]bool{"featureEnabled": true}, recorder.BoolValues)
	})

	t.Run("overwrites rather than aggregating repeated calls", func(t *testing.T) {
		recorder := &metrics.RecorderFake{}
		accumulator := metrics.NewAccumulator(recorder)

		accumulator.RecordBool("featureEnabled", true)
		accumulator.RecordBool("featureEnabled", false)

		assert.Equal(t, map[string]bool{"featureEnabled": false}, recorder.BoolValues)
	})
}

func TestAccumulator_KeepMaximum(t *testing.T) {
	tests := []struct {
		name     string
		values   []int
		expected int
	}{
		{name: "keeps a later larger value", values: []int{3, 9}, expected: 9},
		{name: "keeps an earlier larger value", values: []int{9, 3}, expected: 9},
		{name: "keeps the largest of many", values: []int{3, 9, 4, 1}, expected: 9},
		// a first report of 0 must still land, otherwise the key is missing entirely
		{name: "records a single zero", values: []int{0}, expected: 0},
		{name: "prefers any value over zero", values: []int{0, 2}, expected: 2},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := &metrics.RecorderFake{}
			accumulator := metrics.NewAccumulator(recorder)

			for _, value := range test.values {
				accumulator.KeepMaximum("durationMs", value)
			}

			assert.Equal(t, map[string]int{"durationMs": test.expected}, recorder.IntValues)
		})
	}
}

func TestAccumulator_WithoutRecorder(t *testing.T) {
	// Callers hold an Accumulator unconditionally, so one without a recorder has to stay usable.
	for name, accumulator := range map[string]*metrics.Accumulator{
		"nil recorder":    metrics.NewAccumulator(nil),
		"nil accumulator": nil,
	} {
		t.Run(name+" discards every value", func(t *testing.T) {
			assert.False(t, accumulator.Recording())

			assert.NotPanics(t, func() {
				accumulator.AddToSum("files", 2)
				accumulator.KeepMaximum("durationMs", 5)
				accumulator.RecordBool("featureEnabled", true)
			})
		})
	}

	t.Run("reports recording with a recorder", func(t *testing.T) {
		assert.True(t, metrics.NewAccumulator(&metrics.RecorderFake{}).Recording())
	})
}

// Several operations of one invocation may report concurrently, so no update may be lost.
// Run under -race to also cover the accumulator's own state.
func TestAccumulator_ConcurrentUpdates(t *testing.T) {
	const (
		writers            = 8
		updatesPerWriter   = 50
		expectedTotalFiles = writers * updatesPerWriter
	)

	recorder := &metrics.RecorderFake{}
	accumulator := metrics.NewAccumulator(recorder)

	var wg sync.WaitGroup
	wg.Add(writers)
	for writer := range writers {
		go func() {
			defer wg.Done()
			for range updatesPerWriter {
				accumulator.AddToSum("files", 1)
				accumulator.KeepMaximum("durationMs", writer)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, expectedTotalFiles, recorder.IntValues["files"])
	assert.Equal(t, writers-1, recorder.IntValues["durationMs"])
}
