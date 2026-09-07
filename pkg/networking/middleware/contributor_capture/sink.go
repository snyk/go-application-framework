package contributor_capture

import "github.com/snyk/go-application-framework/internal/contributors"

//go:generate go tool github.com/golang/mock/mockgen -source=sink.go -destination sink_mock_test.go -package contributor_capture_test

// Sink is the mechanism by which this middleware reports captured entities. It
// is call synchronously from the middleware, and so is required to be fast and
// non-blocking.
type Sink interface {
	RecordEntity(entityType contributors.EntityType, entityID string)
	RecordMiss(reason contributors.MissReason)
}
