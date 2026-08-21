package contributor_capture

import "github.com/snyk/go-application-framework/internal/contributors"

// Sink is the mechanism by which this middleware reports captured entities. It
// is call synchronously from the middleware, and so is required to be fast and
// non-blocking.
type Sink interface {
	RecordEntity(entityType contributors.EntityType, entityID, interactionID string)
}

// SinkProvider resolves the current Sink. If it returns nil, this is
// a signal that capture is disabled and the middleware does no work.
type SinkProvider func() Sink
