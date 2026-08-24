package contributors

import (
	"sync"
	"sync/atomic"

	"github.com/snyk/go-application-framework/internal/apiclients/contributors_ingest"
)

// EntityType identifies the kind of Snyk entity a captured ID refers to.
type EntityType = contributors_ingest.EntityType

// EntityTypeProject identifies a captured ID as a Snyk project ID.
const EntityTypeProject = contributors_ingest.EntityTypeProject

// EntityTypeRevision identifies a captured ID as a Snyk revision ID.
const EntityTypeRevision = contributors_ingest.EntityTypeRevision

var captureEnabled atomic.Bool

// Enable turns on contributor capture for this process.
func Enable() {
	captureEnabled.Store(true)
}

// ResetCaptureForTest disables contributor capture until Enable is called again.
func ResetCaptureForTest() {
	captureEnabled.Store(false)
}

var singleton = &contributorSink{recordsByInteractionID: make(map[string]entityRecord)}

// GetSink returns the active contributor-capture sink, or nil if capture
// has not been enabled. If GetSink returns non-nil, it will keep doing so
// for the rest of the process.
func GetSink() *contributorSink {
	if !captureEnabled.Load() {
		return nil
	}
	return singleton
}

type entityRecord struct {
	entityType EntityType
	entityID   string
}

type contributorSink struct {
	mu                     sync.Mutex
	recordsByInteractionID map[string]entityRecord
}

// RecordEntity records the first entity seen for a given interaction ID, and
// does nothing on subsequent calls for the same interaction ID.
func (s *contributorSink) RecordEntity(entityType EntityType, entityID, interactionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.recordsByInteractionID[interactionID]; exists {
		return
	}
	s.recordsByInteractionID[interactionID] = entityRecord{entityType: entityType, entityID: entityID}
}

// Get returns the entity type and ID recorded for interactionID, if any,
// and removes it from the sink.
func (s *contributorSink) Get(interactionID string) (entityType EntityType, entityID string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.recordsByInteractionID[interactionID]
	if !exists {
		return "", "", false
	}
	delete(s.recordsByInteractionID, interactionID)
	return record.entityType, record.entityID, true
}
