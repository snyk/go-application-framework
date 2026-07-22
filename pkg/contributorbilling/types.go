package contributorbilling

import (
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

// Contributor holds one git author email and their most recent commit in the collection window.
type Contributor struct {
	Email            string
	LatestCommitDate time.Time
}

// BillingItem is one project scope within a single ingest POST.
type BillingItem struct {
	ProjectID    string
	Contributors []Contributor
	// RepoPath overrides EmitOptions.RepoPath for contributor collection on this item.
	RepoPath string
}

// EmitOptions configures a fire-and-forget contributor billing POST.
type EmitOptions struct {
	HTTPClient *http.Client
	IngestURL  string
	AuthHeader string
	Capability string
	ScopeID    string
	Items      []BillingItem

	// RepoPath is the default git root when CollectContributors fills empty item slices.
	RepoPath            string
	CollectContributors bool

	Timeout  time.Duration
	Logger   *zerolog.Logger
	OnResult func(Result)
}

// ResultStatus describes the outcome of an emit attempt.
type ResultStatus string

const (
	ResultStatusEmitted ResultStatus = "emitted"
	ResultStatusSkipped ResultStatus = "skipped"
	ResultStatusFailed  ResultStatus = "failed"
)

// SkipReason explains why an emit was not attempted.
type SkipReason string

const (
	SkipReasonEmptyItems        SkipReason = "empty_items"
	SkipReasonMissingProjectID  SkipReason = "missing_project_id"
	SkipReasonMissingCapability SkipReason = "missing_capability"
	SkipReasonMissingScopeID    SkipReason = "missing_scope_id"
)

// FailReason explains why an emit POST failed.
type FailReason string

const (
	FailReasonHTTPError        FailReason = "http_error"
	FailReasonTimeout          FailReason = "timeout"
	FailReasonCanceled         FailReason = "canceled"
	FailReasonMarshalError     FailReason = "marshal_error"
	FailReasonMissingIngestURL FailReason = "missing_ingest_url"
	FailReasonRequestError     FailReason = "request_error"
)

// Result is delivered via OnResult after the async emit completes or is skipped.
type Result struct {
	Status     ResultStatus
	SkipReason SkipReason
	FailReason FailReason
	HTTPStatus int
	Err        error
	// ContributorCollectionErr is set when git collection failed but the POST still ran.
	ContributorCollectionErr error
}
