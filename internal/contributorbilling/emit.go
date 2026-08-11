package contributorbilling

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
	entitlements_service "github.com/snyk/go-application-framework/internal/contributorbilling/client/entitlements_service"
)

// EmitContributorBilling fires an async POST to entitlements-service ingest on the package default Emitter.
// Prefer NewEmitter() when the host process may run multiple workflows or billing scopes concurrently.
// It returns immediately and never surfaces an error that should fail the caller's command.
// Short-lived hosts (e.g. the CLI) must call Wait or WaitWithTimeout before process exit.
func EmitContributorBilling(ctx context.Context, opts EmitOptions) {
	defaultEmitter.EmitContributorBilling(ctx, opts)
}

func cloneItem(item BillingItem) BillingItem {
	cloned := BillingItem{
		EntityID:   item.EntityID,
		EntityType: item.EntityType,
	}
	if item.RepoPath != "" {
		cloned.RepoPath = resolveRepoPath(item.RepoPath)
	}
	if len(item.Contributors) > 0 {
		cloned.Contributors = make([]Contributor, len(item.Contributors))
		copy(cloned.Contributors, item.Contributors)
	}
	return cloned
}

func (opts EmitOptions) withDefaults() EmitOptions {
	opts.ScopeID = strings.TrimSpace(opts.ScopeID)
	opts.Capability = strings.TrimSpace(opts.Capability)
	opts.RepoPath = resolveRepoPath(opts.RepoPath)
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultTimeout
	}
	if opts.Logger == nil {
		nop := zerolog.Nop()
		opts.Logger = &nop
	}
	return opts
}

func emitContributorBilling(parent context.Context, opts EmitOptions) Result {
	opts.Item.EntityID = strings.TrimSpace(opts.Item.EntityID)
	if opts.Item.EntityID == "" {
		skipReason := SkipReasonMissingEntityID
		logSkip(opts.Logger, skipReason)
		return Result{Status: ResultStatusSkipped, SkipReason: skipReason}
	}

	if opts.Item.EntityType != "" {
		opts.Item.EntityType = strings.TrimSpace(opts.Item.EntityType)
		if !isKnownEntityType(opts.Item.EntityType) {
			skipReason := SkipReasonInvalidEntityType
			logSkip(opts.Logger, skipReason)
			return Result{Status: ResultStatusSkipped, SkipReason: skipReason}
		}
	}

	if skipReason := validateRequiredFields(opts); skipReason != "" {
		logSkip(opts.Logger, skipReason)
		return Result{Status: ResultStatusSkipped, SkipReason: skipReason}
	}

	if strings.TrimSpace(opts.IngestURL) == "" {
		return missingIngestURLResult(opts.Logger)
	}

	var collectionErr error
	if opts.CollectContributors {
		collectionErr = fillContributors(&opts.Item, opts.RepoPath, time.Now(), opts.Logger)
	}

	dedupeContributor(&opts.Item)

	result := postIngest(parent, opts, opts.Item)
	if collectionErr != nil {
		result.ContributorCollectionErr = collectionErr
	}
	return result
}

func validateRequiredFields(opts EmitOptions) SkipReason {
	if opts.Capability != "" && !isKnownCapability(opts.Capability) {
		return SkipReasonInvalidCapability
	}
	if opts.ScopeID == "" {
		return SkipReasonMissingScopeID
	}
	return ""
}

func isKnownCapability(capability string) bool {
	switch capability {
	case CapabilityOSS, CapabilityCode, CapabilityIaC:
		return true
	default:
		return false
	}
}

func isKnownEntityType(entityType string) bool {
	switch entityType {
	case EntityTypeProject, EntityTypeTarget, EntityTypeRevision:
		return true
	default:
		return false
	}
}

func missingIngestURLResult(logger *zerolog.Logger) Result {
	err := errors.New("ingest URL is required")
	logger.Debug().Err(err).Msg("contributor billing: missing ingest URL")
	return Result{Status: ResultStatusFailed, FailReason: FailReasonMissingIngestURL, Err: err}
}

func postIngest(parent context.Context, opts EmitOptions, item BillingItem) Result {
	client, err := entitlements_service.NewIngestClient(opts.HTTPClient, opts.IngestURL)
	if err != nil {
		opts.Logger.Debug().Err(err).Msg("contributor billing: failed to create ingest client")
		return Result{Status: ResultStatusFailed, FailReason: FailReasonRequestError, Err: err}
	}

	baseCtx := context.WithoutCancel(parent)
	itemCtx, cancel := context.WithTimeout(baseCtx, opts.Timeout)
	defer cancel()

	request := buildIngestRequest(item, opts.Logger)
	result := postSingleIngest(itemCtx, client, opts, request)

	if result.Status == ResultStatusEmitted {
		opts.Logger.Debug().Int("status", result.HTTPStatus).Msg("contributor billing: emitted")
		return result
	}

	opts.Logger.Debug().
		Str("fail_reason", string(result.FailReason)).
		Msg("contributor billing: ingest failed")

	return result
}

func postSingleIngest(
	ctx context.Context,
	client *entitlements_service.IngestClient,
	opts EmitOptions,
	request entitlements_service.IngestRequest,
) Result {
	resp, err := client.CreateContributingDevs(ctx, opts.ScopeID, opts.AuthHeader, request)
	if err != nil {
		failReason := FailReasonHTTPError
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			failReason = FailReasonTimeout
		}
		opts.Logger.Debug().Err(err).Str("reason", string(failReason)).Msg("contributor billing: POST failed")
		return Result{Status: ResultStatusFailed, FailReason: failReason, Err: err}
	}

	if resp.StatusCode() == http.StatusCreated {
		return Result{Status: ResultStatusEmitted, HTTPStatus: resp.StatusCode()}
	}

	err = fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode())
	opts.Logger.Debug().Int("status", resp.StatusCode()).Msg("contributor billing: unexpected HTTP status")
	return Result{
		Status:     ResultStatusFailed,
		FailReason: FailReasonHTTPError,
		HTTPStatus: resp.StatusCode(),
		Err:        err,
	}
}

func logSkip(logger *zerolog.Logger, reason SkipReason) {
	logger.Info().Str("reason", string(reason)).Msg("contributor billing: skipped emit")
}
