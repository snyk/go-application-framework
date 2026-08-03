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

func cloneItems(items []BillingItem) []BillingItem {
	if len(items) == 0 {
		return nil
	}

	cloned := make([]BillingItem, len(items))
	for i, item := range items {
		cloned[i] = BillingItem{
			EntityID:   item.EntityID,
			EntityType: item.EntityType,
		}
		if item.RepoPath != "" {
			cloned[i].RepoPath = resolveRepoPath(item.RepoPath)
		}
		if len(item.Contributors) > 0 {
			cloned[i].Contributors = append([]Contributor(nil), item.Contributors...)
		}
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
	items, skipReason := filterItems(opts.Items)
	if len(items) == 0 {
		logSkip(opts.Logger, skipReason)
		return Result{Status: ResultStatusSkipped, SkipReason: skipReason}
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
		collectionErr = fillContributors(items, opts.RepoPath, time.Now(), opts.Logger)
	}

	dedupeContributorsForItems(items)

	result := postIngest(parent, opts, items)
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

func fillContributors(items []BillingItem, defaultRepoPath string, now time.Time, logger *zerolog.Logger) error {
	needsCollection := false
	for _, item := range items {
		if len(item.Contributors) == 0 {
			needsCollection = true
			break
		}
	}
	if !needsCollection {
		return nil
	}

	cache := make(map[string][]Contributor)
	var firstErr error

	for i := range items {
		if len(items[i].Contributors) > 0 {
			continue
		}

		repoPath := items[i].RepoPath
		if repoPath == "" {
			repoPath = defaultRepoPath
		}

		contributors, cached := cache[repoPath]
		if !cached {
			var err error
			contributors, err = collectContributors(repoPath, now)
			if err != nil {
				logger.Debug().Err(err).Str("repo_path", repoPath).Msg("contributor billing: git collection failed, continuing with empty contributors")
				cache[repoPath] = nil
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			cache[repoPath] = contributors
		}

		items[i].Contributors = contributors
	}

	return firstErr
}

func filterItems(items []BillingItem) ([]BillingItem, SkipReason) {
	if len(items) == 0 {
		return nil, SkipReasonEmptyItems
	}

	filtered := make([]BillingItem, 0, len(items))
	for _, item := range items {
		entityID := strings.TrimSpace(item.EntityID)
		if entityID == "" {
			continue
		}
		item.EntityID = entityID
		filtered = append(filtered, item)
	}

	if len(filtered) == 0 {
		return nil, SkipReasonMissingEntityID
	}

	return filtered, ""
}

func missingIngestURLResult(logger *zerolog.Logger) Result {
	err := errors.New("ingest URL is required")
	logger.Debug().Err(err).Msg("contributor billing: missing ingest URL")
	return Result{Status: ResultStatusFailed, FailReason: FailReasonMissingIngestURL, Err: err}
}

func postIngest(parent context.Context, opts EmitOptions, items []BillingItem) Result {
	if strings.TrimSpace(opts.IngestURL) == "" {
		return missingIngestURLResult(opts.Logger)
	}

	client, err := entitlements_service.NewIngestClient(opts.HTTPClient, opts.IngestURL)
	if err != nil {
		opts.Logger.Debug().Err(err).Msg("contributor billing: failed to create ingest client")
		return Result{Status: ResultStatusFailed, FailReason: FailReasonRequestError, Err: err}
	}

	baseCtx := context.WithoutCancel(parent)
	var (
		lastStatus    int
		emitted       int
		failed        int
		failureResult *Result
	)

	for _, item := range items {
		itemCtx, cancel := context.WithTimeout(baseCtx, opts.Timeout)
		request := buildIngestRequest(item, opts.Logger)
		result := postSingleIngest(itemCtx, client, opts, request)
		cancel()

		if result.Status == ResultStatusEmitted {
			emitted++
			lastStatus = result.HTTPStatus
			continue
		}

		failed++
		if failureResult == nil {
			copied := result
			failureResult = &copied
		}
	}

	if failed == 0 {
		opts.Logger.Debug().Int("status", lastStatus).Int("items", len(items)).Msg("contributor billing: emitted")
		return Result{
			Status:       ResultStatusEmitted,
			HTTPStatus:   lastStatus,
			ItemsEmitted: emitted,
		}
	}

	opts.Logger.Debug().
		Int("items_emitted", emitted).
		Int("items_failed", failed).
		Msg("contributor billing: ingest completed with failures")

	aggregated := Result{
		Status:       ResultStatusFailed,
		ItemsEmitted: emitted,
		ItemsFailed:  failed,
	}
	if failureResult != nil {
		aggregated.FailReason = failureResult.FailReason
		aggregated.HTTPStatus = failureResult.HTTPStatus
		aggregated.Err = failureResult.Err
	}
	return aggregated
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
	logger.Debug().Str("reason", string(reason)).Msg("contributor billing: skipped emit")
}
