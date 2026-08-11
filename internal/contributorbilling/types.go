package contributorbilling

import (
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// Contributor holds one git author email and their most recent commit in the collection window.
type Contributor struct {
	Email            string
	LatestCommitDate time.Time
}

// BillingItem is the entity scope emitted as an ingest POST.
type BillingItem struct {
	// EntityID is the UUID portion of contributors_entity_id (paired with EntityType).
	// Required.
	EntityID string
	// EntityType is the ES ingest entity prefix (project, target, revision). Defaults to project.
	EntityType   string
	Contributors []Contributor
	// RepoPath overrides EmitOptions.RepoPath for contributor collection.
	RepoPath string
}

// EmitOptions configures a fire-and-forget contributor billing POST.
type EmitOptions struct {
	HTTPClient *http.Client
	IngestURL  string
	AuthHeader string
	// Capability is an optional caller-side telemetry label (e.g. oss, code, iac).
	// It is not sent on the HTTP payload.
	Capability string
	ScopeID    string
	Item       BillingItem

	// Configuration and Engine optionally supply IngestURL, AuthHeader, and HTTPClient
	// via ApplyFromConfiguration when those fields are unset.
	Configuration configuration.Configuration
	Engine        workflow.Engine

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
	SkipReasonMissingEntityID   SkipReason = "missing_entity_id"
	SkipReasonInvalidCapability SkipReason = "invalid_capability"
	SkipReasonInvalidEntityType SkipReason = "invalid_entity_type"
	SkipReasonMissingScopeID    SkipReason = "missing_scope_id"
)

// FailReason explains why an emit POST failed.
type FailReason string

const (
	FailReasonHTTPError        FailReason = "http_error"
	FailReasonTimeout          FailReason = "timeout"
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
