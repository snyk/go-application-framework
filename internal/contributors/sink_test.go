package contributors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetForTesting clears the enabled flag and sink state for test isolation.
// Tests that call Enable() should call this in cleanup to allow other tests to run concurrently.
func resetForTesting() {
	captureEnabled.Store(false)
	singleton.mu.Lock()
	singleton.recordsByInteractionID = make(map[string]entityRecord)
	singleton.mu.Unlock()
}

func TestGetSink(t *testing.T) {
	t.Cleanup(resetForTesting)

	assert.Nil(t, GetSink(), "capture must be disabled until Enable is called")

	Enable()

	sink := GetSink()
	require.NotNil(t, sink)
	assert.NotPanics(t, func() {
		sink.RecordEntity(EntityTypeProject, "11111111-1111-4111-8111-111111111111", "urn:snyk:interaction:test")
	})
}

func TestContributorSink_RecordEntity_oneEntityPerInteractionID(t *testing.T) {
	t.Parallel()
	sink := &contributorSink{recordsByInteractionID: make(map[string]entityRecord)}

	sink.RecordEntity(EntityTypeProject, "11111111-1111-4111-8111-111111111111", "urn:snyk:interaction:one")
	sink.RecordEntity(EntityTypeProject, "22222222-2222-4222-8222-222222222222", "urn:snyk:interaction:one")

	entityType, entityID, ok := sink.Get("urn:snyk:interaction:one")
	require.True(t, ok)
	assert.Equal(t, EntityTypeProject, entityType)
	assert.Equal(t, "11111111-1111-4111-8111-111111111111", entityID, "returns the first recorded entity")
}

func TestContributorSink_Get_missingInteractionID(t *testing.T) {
	t.Parallel()
	sink := &contributorSink{recordsByInteractionID: make(map[string]entityRecord)}

	_, _, ok := sink.Get("urn:snyk:interaction:unknown")
	assert.False(t, ok)
}

func TestContributorSink_Get_removesEntryAfterRead(t *testing.T) {
	t.Parallel()
	sink := &contributorSink{recordsByInteractionID: make(map[string]entityRecord)}
	sink.RecordEntity(EntityTypeProject, "11111111-1111-4111-8111-111111111111", "urn:snyk:interaction:one")

	_, _, ok := sink.Get("urn:snyk:interaction:one")
	require.True(t, ok)

	_, _, ok = sink.Get("urn:snyk:interaction:one")
	assert.False(t, ok, "entry removed by first read")
	assert.Empty(t, sink.recordsByInteractionID)
}
