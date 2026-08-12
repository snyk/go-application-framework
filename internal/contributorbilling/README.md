# Contributor Billing

Fire-and-forget client for posting Active Contributor billing data to
entitlements-service after successful in-scope CLI commands.

## Purpose

After a successful command (`snyk monitor`, `snyk iac test --report`, `snyk code test --report`),
callers emit contributor usage to the entitlements-service ingest endpoint, which publishes Kafka
billing events.

## Architecture

### Single Item Per Emit

Each `EmitContributorBilling()` call emits exactly **one** billing item (project, target, or revision).
The API accepts a single `BillingItem` for each CLI command. This keeps the contract straightforward: one
emit call → one POST request. If you have 10 repos, make 10 calls.

Note that some CLI commands can create multiple projects (a lot in some cases such as legacy IAC!); but they will only reference one git repository. 

The Entity ID must be Project ID in some cases, because target information is not available to the CLI. For the purposes of collecting active contributors, we are happy to send details for a single project within a target, as when this is later tied to a usage event, the target ID will be used.

Note: It is possible that the project ID sent is later deleted before the usage event is tracked. The active contributor count will still be used in this case if the target still exists.

### Fire-and-Forget Semantics

`EmitContributorBilling` returns immediately and never surfaces an error that should change the
caller's command exit code. The POST runs in a background goroutine detached from parent context
cancellation (but bounded by `Timeout`). Errors never block the caller.

**Why**: Billing is a best-effort side effect. If a POST fails or times out, the user's action
(scan, test, monitor) succeeded; billing is ancillary and should not fail the command.

### Isolated Emitters

**Prefer `NewEmitter()`** for hosts that may run multiple workflows or billing scopes concurrently
(CLI, IDE, MCP). Each emitter tracks its own in-flight work independently:

```go
fastEmitter := contributorbilling.NewEmitter()
slowEmitter := contributorbilling.NewEmitter()

fastEmitter.EmitContributorBilling(ctx, fastOpts)
slowEmitter.EmitContributorBilling(ctx, slowOpts)

fastEmitter.WaitWithTimeout(100 * time.Millisecond)   // waits for fastOpts only
slowEmitter.WaitWithTimeout(2 * time.Second)          // waits for slowOpts only
```

The package also provides `EmitContributorBilling()` (package-level function) that uses a shared
default emitter. Use only if you control the entire process's billing lifecycle.

## Entry point

```go
emitter := contributorbilling.NewEmitter()
defer emitter.WaitWithTimeout(contributorbilling.DefaultTimeout)

opts := contributorbilling.EmitOptions{
    // Required
    Item:    BillingItem{EntityID: projectID},  // EntityType defaults to "project"
    ScopeID: orgID,
    
    // Optional
    Capability:          "oss",              // oss, code, iac (telemetry label only)
    CollectContributors: true,               // Run git log to gather contributors
    RepoPath:            ".",                // Git root (for collection)
    
    // Dependency injection
    Configuration: config,
    Engine:        engine,
    Logger:        logger,
    Timeout:       contributorbilling.DefaultTimeout,
    
    // Callback (optional)
    OnResult: func(result contributorbilling.Result) {
        // emitted | skipped | failed telemetry
    },
}
emitter.EmitContributorBilling(ctx, opts)
```

`ApplyFromConfiguration` fills unset `HTTPClient`, `IngestURL`, and `AuthHeader` from
`configuration.Configuration` and `workflow.Engine`. Callers can override explicitly.

## Process lifecycle

Short-lived hosts must wait for in-flight emits before exit, or the POST may be terminated when the
process ends:

```go
emitter := contributorbilling.NewEmitter()
defer emitter.WaitWithTimeout(contributorbilling.DefaultTimeout)

emitter.EmitContributorBilling(ctx, opts)
// ... do other work ...
```

`Wait()` blocks until all in-flight goroutines finish. `WaitWithTimeout(d)` returns false if
deadline elapses first. Since each emit is a single item (one POST), `DefaultTimeout` is typically
enough.

Repo paths are resolved to absolute paths at emit time, so later working-directory changes cannot
scan the wrong git root.

## Ingest contract

Aligned with entitlements-service `POST /hidden/orgs/{org_id}/contributing_devs?version=2024-10-15`.

Each `BillingItem` is emitted as a separate JSON:API POST:

```
POST {IngestURL}/hidden/orgs/{org_id}/contributing_devs?version=2024-10-15
Authorization: token <SNYK_TOKEN>
Content-Type: application/vnd.api+json
```

```json
{
  "data": {
    "type": "contributing_devs",
    "attributes": {
      "contributors_entity_type": "project",
      "contributors_entity_id": "<project-uuid>",
      "contributors": [
        {
          "email": "dev@example.com",
          "commit_date": "2026-01-15T12:00:00Z"
        }
      ]
    }
  }
}
```

- Expected success response: **201 Created**
- `ScopeID` is the org UUID path parameter
- `BillingItem.EntityID` is the entity UUID; `BillingItem.EntityType` defaults to `project` (`project`, `target`, or `revision`)
- `IngestURL` may include an optional path prefix (preserved by the ingest client)

See `testdata/golden_ingest_payload.json` for a golden fixture.

## Contributor collection

When `CollectContributors: true`, the package runs git log for items with empty `Contributors`:

- **Window filtering**: last **90 days** by **commit date** (when merged/pushed to this repo)
  - However, the timestamp sent in events is **authored date** (when code was originally written)
  - This distinction matters: cherry-picked or rebased commits may have old author dates but recent commit dates
  - Matches entitlements-service SCM active contributors pipeline logic
- **Max commits**: **500** (`MaxCommitsInGitLog`), walking newest-first from HEAD
  - If the window has >500 commits, older in-window commits are not scanned
- **Deduplication**: by email (case-insensitive, with whitespace trimmed)
  - Keeps the most recent **authored** date per email
  - **Empty emails are always filtered out** before POST
- **Errors don't block emission**: git collection failures are logged and returned in
  `Result.ContributorCollectionErr`, but the POST still fires with empty contributors

Git log collection uses `pkg/utils/git.ListContributors`. Callers that need contributor data
without emitting should use `pkg/utils/git` directly.

## Nuances & Gotchas

### OnResult Panics Are Suppressed

If the `OnResult` callback panics, the panic is caught, logged at warn level, and the emitter
continues cleanly. This prevents one bad callback from crashing the process.

```go
EmitContributorBilling(ctx, EmitOptions{
    OnResult: func(r Result) {
        panic("oops")  // ← Caught and logged; emitter continues
    },
})
```

### Single Emit = Single Item = Single POST

No batching. If you have 10 repos, make 10 calls. This is intentional—the endpoint accepts one
item per request anyway.

### Empty Emails Are Filtered

Contributors with empty email addresses are skipped before the POST, even if they have a valid
commit date. This applies regardless of how many other contributors exist.

```go
// POST will only contain alice; bob (empty email) is dropped
EmitContributorBilling(ctx, EmitOptions{
    Item: BillingItem{
        EntityID: "proj",
        Contributors: []Contributor{
            {Email: "alice@example.com", LatestCommitDate: now},
            {Email: "", LatestCommitDate: now},  // ← Filtered out
        },
    },
})
```

### Skips When Collection Returns Empty

When `CollectContributors: true`, if contributor collection finds no results (git log error or no
commits in window), the emit is skipped. The collection error, if any, is captured in
`Result.ContributorCollectionErr` for caller inspection.

If collection is not requested (`CollectContributors: false`), the emit proceeds even with empty
contributors (caller's explicit choice).

```go
// CollectContributors: true, git log fails or finds no commits → skip
EmitContributorBilling(ctx, EmitOptions{
    CollectContributors: true,
    RepoPath: "/nonexistent",
    Item: BillingItem{EntityID: "proj"},
})
// Result.Status == ResultStatusSkipped
// Result.SkipReason == "empty_contributors"
// Result.ContributorCollectionErr is set (if collection failed)

// CollectContributors: false, no contributors provided → emit proceeds
EmitContributorBilling(ctx, EmitOptions{
    Item: BillingItem{EntityID: "proj"},  // no Contributors
})
// Result.Status == ResultStatusEmitted (empty contributors list POSTed)
```

### Whitespace is Trimmed

Leading/trailing whitespace in `EntityID` and `EntityType` is automatically trimmed.

```go
// "  project-1  " becomes "project-1"
// "  target  " becomes "target"
EmitContributorBilling(ctx, EmitOptions{
    Item: BillingItem{
        EntityID:   "  project-1  ",
        EntityType: "  target  ",
    },
})
```

## Metrics

Callers can record emit outcomes (success/skip/fail counts) by providing a `MetricsRecorder`:

```go
emitter.EmitContributorBilling(ctx, EmitOptions{
    // ... other fields ...
    MetricsRecorder: analytics,  // pass pkg/analytics.Analytics or any metrics.Recorder
})
// Metrics recorded:
// - "contributor_billing.emitted" (integer count)
// - "contributor_billing.skipped" + "contributor_billing.skipped.reason" (string)
// - "contributor_billing.failed" + "contributor_billing.failed.reason" (string)
```

The recorder is optional; if nil, no metrics are recorded.

## Concurrency

`Emitter` is thread-safe. Multiple goroutines can safely call emit/wait on the same emitter.

- In-flight count is guarded by `sync.Mutex`
- Wait coordination uses `sync.Cond` (condition variable)
- Each emitter tracks pending goroutines independently
- When count reaches zero, a broadcast wakes all waiting `WaitWithTimeout()` calls

## Analytics policy

**Billing is not gated on analytics flags.**

- `--disable-analytics` / `ANALYTICS_DISABLED` must **not** skip the billing POST after a successful command
- Users must not opt out of billing via the analytics flag
- When emit is invoked, git log still runs for contributor collection (even if analytics is disabled)
- Callers should invoke emit after command success; this package does not read analytics env vars

The legacy Registry usage path coupling analytics to `getContributors()` is accidental and does not
apply here.

## Skip and failure reasons

| Outcome | Reason | When |
|---------|--------|------|
| `skipped` | `missing_entity_id` | `EntityID` is empty |
| `skipped` | `invalid_capability` | Non-empty `Capability` is not one of `oss`, `code`, or `iac` |
| `skipped` | `invalid_entity_type` | Non-empty `EntityType` is not one of `project`, `target`, or `revision` |
| `skipped` | `missing_scope_id` | `ScopeID` is empty |
| `skipped` | `empty_contributors` | Collection was requested but returned no contributors (no POST made; check `ContributorCollectionErr` for collection errors) |
| `failed` | `missing_ingest_url` | `IngestURL` is empty |
| `failed` | `request_error` | HTTP request could not be constructed |
| `failed` | `http_error` | Network error or non-201 response (`Result.Err` set for unexpected status) |
| `failed` | `timeout` | POST exceeded `Timeout` (default 5s) |
| `emitted` | — | POST returned HTTP 201 |

## Future call sites (out of scope for this package)

| Repo | When | Entity ID source |
|------|------|------------------|
| cliv2 + legacy TS | Monitor / IaC `--report` (TS path) success | capture middleware project UUIDs |
| cli-extension-os-flows | Dragonfly monitor success | monitor response project public ID |
| code-client-go | Native `--report` success | `ResultMetaData.TargetId` as target entity |

Not in scope: IaC native extension changes (legacy cliv2 capture only for v1), SCLE Code `--report`, container/docker monitor.

## Out of scope

- Retries, compression, rate limiting
- ES ingest implementation / Kafka
- Wiring into extension repos
