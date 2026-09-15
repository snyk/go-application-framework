package contributors

import (
	"context"
	"sync/atomic"

	"github.com/google/uuid"

	"github.com/snyk/go-application-framework/internal/metrics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Report emits contributors and records the result.
func Report(ctx context.Context, engine workflow.Engine, sink *Sink) {
	report(ctx, engine, sink, engine.GetAnalytics())
}

// report implements the functionality for [Report]. This unexported variant uses an
// interface instead of getting the analytics.Analytics implementation from the engine
// to facilitate testing.
func report(ctx context.Context, engine workflow.Engine, sink *Sink, recorder metrics.Recorder) {
	item, alreadyReported := sink.take()
	if alreadyReported {
		return
	}

	if item == nil {
		result := missResult(sink.miss())
		recorder.AddExtensionStringValue(analyticsKeyResult, string(result))
		return
	}

	// Record a provisional timeout value, to be overwritten later unless a timeout occurs.
	recorder.AddExtensionStringValue(analyticsKeyResult, string(resultTimedOut))

	result, count := emit(ctx, engine, *item)

	recorder.AddExtensionStringValue(analyticsKeyResult, string(result))
	if result == resultEmitted {
		recorder.AddExtensionIntegerValue(analyticsKeyCount, count)
	}
}

// emit reports contributors for the captured entity, returning the outcome and how
// many contributors were collected, or zero when a failure occurs.
func emit(ctx context.Context, engine workflow.Engine, item Item) (collectionResult, int) {
	logger := engine.GetLogger()
	config := engine.GetConfiguration()

	orgID, err := config.GetStringWithError(configuration.ORGANIZATION)
	if err != nil {
		return resultOrgIDInvalid, 0
	}
	orgUUID, err := uuid.Parse(orgID)
	if err != nil {
		return resultOrgIDInvalid, 0
	}

	dirs := config.GetStringSlice(configuration.INPUT_DIRECTORY)
	if len(dirs) == 0 || dirs[0] == "" {
		return resultNoInputDirectory, 0
	}

	emitter, err := NewEmitter(engine.GetNetworkAccess().GetHttpClient(), config, logger)
	if err != nil {
		return resultEmitterInitFailed, 0
	}

	count, err := emitter.Emit(ctx, dirs[0], orgUUID, item)
	if err != nil {
		result := emitResult(err)
		return result, count
	}

	return resultEmitted, count
}

type Sink struct {
	item       atomic.Pointer[Item]
	taken      atomic.Bool
	missReason atomic.Int32
}

// RecordEntity records the first entity reported to the sink for later emission.
func (s *Sink) RecordEntity(entityType EntityType, entityID string) {
	s.item.CompareAndSwap(nil, &Item{EntityType: entityType, EntityID: entityID})
}

// RecordMiss keeps the first reason for a miss reported for analytics.
func (s *Sink) RecordMiss(reason MissReason) {
	s.missReason.CompareAndSwap(int32(MissNone), int32(reason))
}

func (s *Sink) miss() MissReason {
	return MissReason(s.missReason.Load())
}

// take hands the captured entity to the first caller after a capture.
// alreadyTaken distinguishes the nil item case where nothing was recorded from
// the case where it has already been emitted.
func (s *Sink) take() (item *Item, alreadyTaken bool) {
	captured := s.item.Load()
	if captured == nil {
		return nil, false
	}

	if !s.taken.CompareAndSwap(false, true) {
		return nil, true
	}

	return captured, false
}
