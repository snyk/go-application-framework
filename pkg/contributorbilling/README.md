# Contributor Billing

Fire-and-forget client for posting CLI Active Contributor billing data to
entitlements-service after successful in-scope commands.

## Purpose

After a successful command (`snyk monitor`, `snyk iac test --report`, `snyk code test --report`),
extensions call `EmitContributorBilling` with the org scope, entity ID(s), and optional git
contributor snapshot. The entitlements-service ingest endpoint produces Kafka billing events.

This package is **Part 1** of CLI delivery. Wiring into extension repos is handled in separate
tickets.

## Entry point

Use the package default for single-host CLI wiring, or create an `Emitter` when a host needs
isolated in-flight tracking (tests, multiple billing scopes in one process):

```go
emitter := contributorbilling.NewEmitter()
defer emitter.WaitWithTimeout(contributorbilling.DefaultTimeout)

emitter.EmitContributorBilling(ctx, contributorbilling.EmitOptions{
    HTTPClient: client,
    IngestURL:  apiURL,
    AuthHeader: "token " + token,
    Capability: contributorbilling.CapabilityOSS, // oss | code | iac — caller-side gating only
    ScopeID:    orgID,
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
})
```

Package-level helpers delegate to a shared default `Emitter`:

```go
contributorbilling.EmitContributorBilling(ctx, opts)
```

`EmitContributorBilling` is fire-and-forget: it returns immediately and never surfaces an error
that should change the caller command exit code. The POST runs in a background goroutine detached
from parent context cancellation (bounded by `Timeout`).

## Process lifecycle

Short-lived hosts such as the CLI must wait for in-flight emits before exit, or the POST may be
terminated when the process ends:

```go
defer contributorbilling.WaitWithTimeout(contributorbilling.DefaultTimeout)

contributorbilling.EmitContributorBilling(ctx, opts)
```

`Wait` blocks until all in-flight goroutines finish. `WaitWithTimeout` returns false if the deadline
elapses first. Skipped emits (empty items, missing fields) still complete synchronously inside the
goroutine and are included in the wait count.

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
- `Capability` is validated client-side for telemetry/gating; it is not sent on the HTTP payload

See `testdata/golden_ingest_payload.json` for a golden fixture.

## Contributor collection

When `CollectContributors` is true, the package runs git log for items with empty `Contributors`:

- Window: last **90 days** (`ContributingDeveloperPeriodDays`)
- Max commits scanned: **500** (`MaxCommitsInGitLog`), walking **newest commits from HEAD** only — if the window contains more than 500 commits, older in-window commits are not scanned
- Per email: keep the **most recent** commit timestamp
- Sorted by email for stable JSON
- Non-git or empty repo: empty contributors, no error
- `EmitOptions.RepoPath` is the default git root; set `BillingItem.RepoPath` to override per entity when one emit spans multiple directories
- Git collection failures are surfaced on `Result.ContributorCollectionErr` while the POST still proceeds with empty contributors for affected items

Semantics align with:

- `snyk/cli` → `src/lib/monitor/dev-count-analysis.ts` (`getContributors`)
- `cli-extension-iac` → `internal/git/contributors.go` (`ListContributors`)
- Git log collection uses `pkg/utils/git.ListContributors`

Callers that need contributor data without emitting should use `pkg/utils/git` directly.

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
| `skipped` | `missing_capability` | `Capability` is empty |
| `skipped` | `invalid_capability` | `Capability` is not one of `oss`, `code`, or `iac` |
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

| Repo | When | Capability | Entity ID source |
|------|------|------------|------------------|
| cliv2 + legacy TS | Monitor / IaC share success | `oss` / `iac` | capture middleware project IDs → `project:<uuid>` |
| cli-extension-os-flows | Dragonfly monitor success | `oss` | monitor response project public ID |
| cli-extension-iac | ShareResultsRegistry (Path B) | `iac` | share response project public ID |
| code-client-go | Native `--report` success | `code` | `ResultMetaData.TargetId` as `target:<uuid>` |

Not in scope: IaC Path C (cloud upload), SCLE Code `--report`, container/docker monitor.

## Out of scope

- Retries, compression, rate limiting
- ES ingest implementation / Kafka
- Wiring into extension repos
