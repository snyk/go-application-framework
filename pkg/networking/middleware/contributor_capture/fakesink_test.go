package contributor_capture_test

import (
	"sync"

	"github.com/snyk/go-application-framework/internal/contributors"
)

type fakeRecord struct {
	EntityType contributors.EntityType
	EntityID   string
}

type fakeSink struct {
	mu      sync.Mutex
	records []fakeRecord
}

func newFakeSink() *fakeSink {
	return &fakeSink{}
}

func (s *fakeSink) RecordEntity(entityType contributors.EntityType, entityID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, fakeRecord{
		EntityType: entityType,
		EntityID:   entityID,
	})
}

func (s *fakeSink) Records() []fakeRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]fakeRecord, len(s.records))
	copy(out, s.records)
	return out
}
