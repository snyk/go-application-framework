# Contributor Billing

Fire-and-forget client for posting Active Contributor billing data to
entitlements-service after successful in-scope CLI commands.

## Purpose

After a successful command (`snyk monitor`, `snyk iac test --report`, `snyk code test --report`),
callers emit contributor usage to the entitlements-service ingest endpoint, which publishes Kafka
billing events.

This package lives under `internal/contributorbilling/` (not public GAF API). CLI hosts use the thin
`pkg/clibilling` facade for shared emit/wait at command teardown; capture middleware is IANDT-238.

## Entry point

**Prefer `NewEmitter()`** for hosts that may run multiple workflows or billing scopes in one process
(CLI, IDE, MCP). The package-level helpers use a shared default emitter and are convenient for
simple single-scope hosts only.

```go
emitter := contributorbilling.NewEmitter()
defer emitter.WaitWithTimeout(contributorbilling.WaitBudget(len(items), contributorbilling.DefaultTimeout))

opts := contributorbilling.EmitOptions{
    Configuration: config,
    Engine:        engine,
    ScopeID:       orgID,
    Items: []contributorbilling.BillingItem{
        {EntityID: projectID}, // EntityType defaults to project → contributors_entity_id project:<uuid>
    },
    RepoPath:            ".",
    CollectContributors: true,
    Timeout:             contributorbilling.DefaultTimeout,
    Logger:              logger,
    OnResult: func(result contributorbilling.Result) {
        // emitted | skipped | failed telemetry
    },
}
emitter.EmitContributorBilling(ctx, opts)
```

`ApplyFromConfiguration` fills unset `HTTPClient`, `IngestURL`, and `AuthHeader` from GAF
`configuration.Configuration` and `workflow.Engine` (API URL + auth header). Callers can still
override any field explicitly.

Optional `Capability` (`oss`, `code`, `iac`) is a caller-side telemetry label only; it is not sent
on the HTTP payload and may be omitted.

`EmitContributorBilling` is fire-and-forget: it returns immediately and never surfaces an error
that should change the caller command exit code. The POST runs in a background goroutine detached
from parent context cancellation (bounded per item by `Timeout`).

## Process lifecycle

Short-lived hosts must wait for in-flight emits before exit, or the POST may be terminated when the
process ends:

```go
emitter := contributorbilling.NewEmitter()
defer emitter.WaitWithTimeout(contributorbilling.WaitBudget(len(items), timeout))

emitter.EmitContributorBilling(ctx, opts)
```

`Wait` blocks until all in-flight goroutines finish. `WaitWithTimeout` returns false if the deadline
elapses first. Each `BillingItem` is a separate sequential POST with its own `Timeout` budget, so
use `WaitBudget(itemCount, timeout)` rather than `DefaultTimeout` alone for multi-item emits.

Repo paths passed as `EmitOptions.RepoPath` or `BillingItem.RepoPath` are resolved to absolute
paths at emit time so later working-directory changes cannot scan the wrong git root.

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
      "contributors_entity_id": "project:<project-uuid>",
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

When `CollectContributors` is true, the package runs git log for items with empty `Contributors`:

- Window: last **90 days** (`ContributingDeveloperPeriodDays`) by **author** timestamp
- Max commits scanned: **500** (`MaxCommitsInGitLog`), walking **newest commits from HEAD** only — if the window contains more than 500 commits, older in-window commits are not scanned
- Per email: keep the **most recent** commit timestamp
- Before each emit POST, contributors are deduplicated again by **exact email** (case-sensitive, as git returns), keeping the latest commit date
- Sorted by email for stable JSON
- Non-git or empty repo: empty contributors, no error
- `EmitOptions.RepoPath` is the default git root; set `BillingItem.RepoPath` to override per entity when one emit spans multiple directories
- Git collection failures are surfaced on `Result.ContributorCollectionErr` while the POST still proceeds with empty contributors for affected items

Git log collection uses `pkg/utils/git.ListContributors`. Callers that need contributor data
without emitting should use `pkg/utils/git` directly.

## Analytics policy

**Billing is not gated on analytics flags.**

- `--disable-analytics` / `ANALYTICS_DISABLED` must **not** skip the billing POST after a successful command
- Users must not opt out of billing via the analytics flag
- v1 default: when emit is invoked, git log still runs for contributor collection (even if analytics is disabled)
- Callers should invoke emit after command success; this package does not read analytics env vars

The legacy Registry usage path coupling analytics to `getContributors()` is accidental and does not
apply here.

## Skip and failure reasons

| Outcome | Reason | When |
|---------|--------|------|
| `skipped` | `empty_items` | No items provided |
| `skipped` | `missing_entity_id` | All items missing `EntityID` |
| `skipped` | `invalid_capability` | Non-empty `Capability` is not one of `oss`, `code`, or `iac` |
| `skipped` | `missing_scope_id` | `ScopeID` is empty |
| `failed` | `missing_ingest_url` | `IngestURL` is empty |
| `failed` | `request_error` | HTTP request could not be constructed |
| `failed` | `http_error` | Network error or non-201 response (`Result.Err` set for unexpected status) |
| `failed` | `timeout` | POST exceeded `Timeout` (default 5s) |
| `emitted` | — | All ingest POSTs returned HTTP 201; check `ContributorCollectionErr` if git collection failed |
| `failed` | (see above) | One or more ingest POSTs failed; `ItemsEmitted` / `ItemsFailed` report partial multi-item outcomes |

Items with empty `EntityID` are dropped; remaining valid items are still emitted (one POST each).
Each item gets its own ingest POST and its own `Timeout` budget.

## Future call sites (out of scope for this package)

| Repo | When | Entity ID source |
|------|------|------------------|
| cliv2 + legacy TS | Monitor / IaC `--report` (TS path) success | capture middleware project IDs → `project:<uuid>` |
| cli-extension-os-flows | Dragonfly monitor success | monitor response project public ID |
| code-client-go | Native `--report` success | `ResultMetaData.TargetId` as `target:<uuid>` |

Not in scope: IaC native extension changes (legacy cliv2 capture only for v1), SCLE Code `--report`, container/docker monitor.

## Out of scope

- Retries, compression, rate limiting
- ES ingest implementation / Kafka
- Wiring into extension repos
