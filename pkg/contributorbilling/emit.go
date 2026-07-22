package contributorbilling

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// EmitContributorBilling fires an async POST to entitlements-service ingest.
// It never returns an error that should fail the caller's command.
func EmitContributorBilling(ctx context.Context, opts EmitOptions) {
	opts = opts.withDefaults()
	opts.Items = cloneItems(opts.Items)

	go func(parent context.Context) {
		result := emitContributorBilling(parent, opts)
		if opts.OnResult != nil {
			opts.OnResult(result)
		}
	}(ctx)
}

func cloneItems(items []BillingItem) []BillingItem {
	if len(items) == 0 {
		return nil
	}

	cloned := make([]BillingItem, len(items))
	for i, item := range items {
		cloned[i] = BillingItem{
			ProjectID: item.ProjectID,
			RepoPath:  item.RepoPath,
		}
		if len(item.Contributors) > 0 {
			cloned[i].Contributors = append([]Contributor(nil), item.Contributors...)
		}
	}
	return cloned
}

func (opts EmitOptions) withDefaults() EmitOptions {
	if opts.RepoPath == "" {
		opts.RepoPath = "."
	}
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
	if err := parent.Err(); err != nil {
		opts.Logger.Debug().Err(err).Str("reason", string(FailReasonCanceled)).Msg("contributor billing: context canceled before emit")
		return Result{Status: ResultStatusFailed, FailReason: FailReasonCanceled, Err: err}
	}

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

	body, err := marshalIngestPayload(opts.Capability, opts.ScopeID, items, opts.Logger)
	if err != nil {
		opts.Logger.Debug().Err(err).Msg("contributor billing: failed to marshal ingest payload")
		return Result{Status: ResultStatusFailed, FailReason: FailReasonMarshalError, Err: err}
	}

	result := postIngest(parent, opts, body)
	if collectionErr != nil {
		result.ContributorCollectionErr = collectionErr
	}
	return result
}

func validateRequiredFields(opts EmitOptions) SkipReason {
	if strings.TrimSpace(opts.Capability) == "" {
		return SkipReasonMissingCapability
	}
	if strings.TrimSpace(opts.ScopeID) == "" {
		return SkipReasonMissingScopeID
	}
	return ""
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
		projectID := strings.TrimSpace(item.ProjectID)
		if projectID == "" {
			continue
		}
		item.ProjectID = projectID
		filtered = append(filtered, item)
	}

	if len(filtered) == 0 {
		return nil, SkipReasonMissingProjectID
	}

	return filtered, ""
}

func missingIngestURLResult(logger *zerolog.Logger) Result {
	err := errors.New("ingest URL is required")
	logger.Debug().Err(err).Msg("contributor billing: missing ingest URL")
	return Result{Status: ResultStatusFailed, FailReason: FailReasonMissingIngestURL, Err: err}
}

func postIngest(parent context.Context, opts EmitOptions, body []byte) Result {
	if strings.TrimSpace(opts.IngestURL) == "" {
		return missingIngestURLResult(opts.Logger)
	}

	ctx, cancel := context.WithTimeout(parent, opts.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, opts.IngestURL, bytes.NewReader(body))
	if err != nil {
		opts.Logger.Debug().Err(err).Msg("contributor billing: failed to create request")
		return Result{Status: ResultStatusFailed, FailReason: FailReasonRequestError, Err: err}
	}

	req.Header.Set("Content-Type", "application/json")
	if opts.AuthHeader != "" {
		req.Header.Set("Authorization", opts.AuthHeader)
	}

	client := opts.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		failReason := FailReasonHTTPError
		if errors.Is(err, context.Canceled) || errors.Is(parent.Err(), context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			failReason = FailReasonCanceled
		} else if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			failReason = FailReasonTimeout
		}
		opts.Logger.Debug().Err(err).Str("reason", string(failReason)).Msg("contributor billing: POST failed")
		return Result{Status: ResultStatusFailed, FailReason: failReason, Err: err}
	}
	defer resp.Body.Close()

	if _, copyErr := io.Copy(io.Discard, resp.Body); copyErr != nil {
		opts.Logger.Debug().Err(copyErr).Msg("contributor billing: failed to drain response body")
	}

	if resp.StatusCode == http.StatusAccepted {
		opts.Logger.Debug().Int("status", resp.StatusCode).Msg("contributor billing: emitted")
		return Result{Status: ResultStatusEmitted, HTTPStatus: resp.StatusCode}
	}

	err = fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)
	opts.Logger.Debug().Int("status", resp.StatusCode).Msg("contributor billing: unexpected HTTP status")
	return Result{
		Status:     ResultStatusFailed,
		FailReason: FailReasonHTTPError,
		HTTPStatus: resp.StatusCode,
		Err:        err,
	}
}

func logSkip(logger *zerolog.Logger, reason SkipReason) {
	logger.Debug().Str("reason", string(reason)).Msg("contributor billing: skipped emit")
}
