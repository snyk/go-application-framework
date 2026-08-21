package contributor_capture_test

import (
	"sync"

	"github.com/snyk/go-application-framework/internal/contributors"
	cc "github.com/snyk/go-application-framework/pkg/networking/middleware/contributor_capture"
)

type fakeRecord struct {
	EntityType    contributors.EntityType
	EntityID      string
	InteractionID string
}

type fakeSink struct {
	mu      sync.Mutex
	records []fakeRecord
}

func newFakeSink() *fakeSink {
	return &fakeSink{}
}

func (s *fakeSink) RecordEntity(entityType contributors.EntityType, entityID, interactionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, fakeRecord{
		EntityType:    entityType,
		EntityID:      entityID,
		InteractionID: interactionID,
	})
}

func (s *fakeSink) Records() []fakeRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]fakeRecord, len(s.records))
	copy(out, s.records)
	return out
}

// sinkProviderAlways always returns sink.
func sinkProviderAlways(sink cc.Sink) cc.SinkProvider {
	return func() cc.Sink { return sink }
}

// sinkProviderNone always returns nil, simulating "not capturing right now".
func sinkProviderNone() cc.SinkProvider {
	return func() cc.Sink { return nil }
}
