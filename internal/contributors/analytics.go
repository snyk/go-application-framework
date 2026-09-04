package contributors

import (
	"context"
	"errors"
)

// Analytics keys reporting what the post-invoke hook did with the invocation.
const (
	analyticsKeyResult = "contributors.collection_result"
	analyticsKeyCount  = "contributors.count"
)

// collectionResult is the outcome reported under [analyticsKeyResult].
type collectionResult string

const (
	resultEmitted collectionResult = "emitted"

	// Nothing was captured, so there was no entity to attribute contributors to.
	resultNoRelevantRequest     collectionResult = "no_relevant_request"
	resultCaptureErrorStatus    collectionResult = "capture_error_status"
	resultCaptureBodyTooLarge   collectionResult = "capture_body_too_large"
	resultCaptureBodyUnreadable collectionResult = "capture_body_unreadable"
	resultCaptureNoEntity       collectionResult = "capture_no_entity"
	resultCapturePanic          collectionResult = "capture_panic"

	// An entity was captured, but reporting failed.
	resultOrgIDInvalid      collectionResult = "org_id_invalid"
	resultNoInputDirectory  collectionResult = "no_input_directory"
	resultEmitterInitFailed collectionResult = "emitter_init_failed"
	resultTimedOut          collectionResult = "timed_out"
	resultCollectFailed     collectionResult = "collect_failed"
	resultSubmitFailed      collectionResult = "submit_failed"

	// No contributors were collected.
	resultNotAGitRepo    collectionResult = "not_a_git_repo"
	resultNoContributors collectionResult = "no_contributors"
)

// MissReason explains why a request the contributor_capture middleware matched did not yield an entity.
type MissReason int

const (
	// MissNone means no miss recorded.
	MissNone MissReason = iota

	// MissErrorStatus is a matched request whose response was an HTTP error.
	MissErrorStatus

	// MissBodyTooLarge is a response body too large to parse.
	MissBodyTooLarge

	// MissBodyUnreadable is a request or response body that could not be read.
	MissBodyUnreadable

	// MissNoEntity is a body parsed successfully that held no entity to record.
	MissNoEntity

	// MissPanic is a panic recovered during capture.
	MissPanic
)

// missResult maps what the capture middleware reported to the outcome to record.
func missResult(reason MissReason) collectionResult {
	switch reason {
	case MissErrorStatus:
		return resultCaptureErrorStatus
	case MissBodyTooLarge:
		return resultCaptureBodyTooLarge
	case MissBodyUnreadable:
		return resultCaptureBodyUnreadable
	case MissNoEntity:
		return resultCaptureNoEntity
	case MissPanic:
		return resultCapturePanic
	case MissNone:
		return resultNoRelevantRequest
	default:
		return resultNoRelevantRequest
	}
}

// emitResult maps a failure to emit to the outcome to record.
func emitResult(err error) collectionResult {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return resultTimedOut
	case errors.Is(err, ErrNotAGitRepository):
		return resultNotAGitRepo
	case errors.Is(err, ErrNoContributors):
		return resultNoContributors
	case errors.Is(err, ErrCollect):
		return resultCollectFailed
	default:
		return resultSubmitFailed
	}
}
