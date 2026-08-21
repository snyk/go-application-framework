package capture_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/internal/contributorbilling/capture"
)

func TestCapture_AddAndSnapshot(t *testing.T) {
	t.Parallel()

	bag := capture.NewCapture()
	bag.Add(capture.Record{
		Capability:  capture.CapabilityOSS,
		EntityID:    "11111111-1111-4111-8111-111111111111",
		EntityType:  capture.EntityTypeProject,
		RequestPath: "/v1/monitor/npm",
	})
	bag.Add(capture.Record{EntityID: ""})

	snapshot := bag.Snapshot()
	assert.Len(t, snapshot, 1)
	assert.Equal(t, capture.CapabilityOSS, snapshot[0].Capability)
}

func TestCapture_FirstDedupedRecord(t *testing.T) {
	t.Parallel()

	bag := capture.NewCapture()
	bag.Add(capture.Record{
		Capability: capture.CapabilityOSS,
		EntityID:   "11111111-1111-4111-8111-111111111111",
	})
	bag.Add(capture.Record{
		Capability: capture.CapabilityOSS,
		EntityID:   "22222222-2222-4222-8222-222222222222",
	})

	record, ok := bag.FirstDedupedRecord()
	require.True(t, ok)
	assert.Equal(t, "11111111-1111-4111-8111-111111111111", record.EntityID)
}

func TestCapture_DedupedRecords(t *testing.T) {
	t.Parallel()

	bag := capture.NewCapture()
	bag.Add(capture.Record{
		Capability: capture.CapabilityOSS,
		EntityID:   "11111111-1111-4111-8111-111111111111",
	})
	bag.Add(capture.Record{
		Capability: capture.CapabilityOSS,
		EntityID:   "11111111-1111-4111-8111-111111111111",
	})
	bag.Add(capture.Record{
		Capability: capture.CapabilityIaC,
		EntityID:   "22222222-2222-4222-8222-222222222222",
	})

	deduped := bag.DedupedRecords()
	require.Len(t, deduped, 2)
}

func TestWithCaptureFromContext(t *testing.T) {
	t.Parallel()

	bag := capture.NewCapture()
	ctx := capture.WithCapture(context.Background(), bag)

	assert.Same(t, bag, capture.FromContext(ctx))
	assert.Nil(t, capture.FromContext(context.Background()))
}

func TestRegisterBillableTest(t *testing.T) {
	t.Parallel()

	bag := capture.NewCapture()
	bag.RegisterBillableTest("33333333-3333-4333-8333-333333333333", capture.CapabilityCode)

	capability, ok := bag.BillableTestCapability("33333333-3333-4333-8333-333333333333")
	require.True(t, ok)
	assert.Equal(t, capture.CapabilityCode, capability)
}

func TestPromoteBillableJob(t *testing.T) {
	t.Parallel()

	const (
		jobID  = "11111111-1111-4111-8111-111111111111"
		testID = "22222222-2222-4222-8222-222222222222"
	)

	bag := capture.NewCapture()
	bag.RegisterBillableTest(jobID, capture.CapabilityOSS)

	bag.PromoteBillableJob(jobID, testID)

	_, ok := bag.BillableTestCapability(jobID)
	assert.False(t, ok)

	capability, ok := bag.BillableTestCapability(testID)
	require.True(t, ok)
	assert.Equal(t, capture.CapabilityOSS, capability)
}
