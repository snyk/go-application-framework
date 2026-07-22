# Contributor Billing

Fire-and-forget client for posting CLI Active Contributor billing data to
entitlements-service after successful in-scope commands.

## Purpose

After a successful command (`snyk monitor`, `snyk iac test --report`, `snyk code test --report`),
extensions call `EmitContributorBilling` with the org scope, target ID(s), and optional git
contributor snapshot. The entitlements-service ingest endpoint produces Kafka billing events.

This package is **Part 1** of CLI delivery. Wiring into extension repos is handled in separate
tickets.

## Entry point

```go
contributorbilling.EmitContributorBilling(ctx, contributorbilling.EmitOptions{
    HTTPClient: client,
    IngestURL:  apiURL + contributorbilling.DefaultIngestPath,
    AuthHeader: "token " + token,
    Capability: contributorbilling.CapabilityOSS, // oss | code | iac
    ScopeID:    orgID,
    Items: []contributorbilling.BillingItem{
        {TargetID: targetID},
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

`EmitContributorBilling` is fire-and-forget: it returns immediately and never surfaces an error
that should change the caller command exit code.

## Ingest contract

```
POST {IngestURL}
Authorization: token <SNYK_TOKEN>
Content-Type: application/json
```

```json
{
  "source": "cli",
  "capability": "oss",
  "items": [
    {
      "scope_id": "<org-uuid>",
      "target_id": "<target-uuid>",
      "contributors": [
        {
          "email": "dev@example.com",
          "latest_commit_date": "2026-01-15T12:00:00Z"
        }
      ]
    }
  ]
}
```

- Expected success response: **202 Accepted**
- Callers send `scope_id`, `target_id`, and `contributors`
- `DefaultIngestPath` is a draft constant; confirm against entitlements-service OpenAPI when available

See `testdata/golden_ingest_payload.json` for a multi-item golden fixture (Part 2 TS alignment).

## Contributor collection

When `CollectContributors` is true, the package runs git log for items with empty `Contributors`:

- Window: last **90 days** (`ContributingDeveloperPeriodDays`)
- Max commits scanned: **500** (`MaxCommitsInGitLog`), walking **newest commits from HEAD** only — if the window contains more than 500 commits, older in-window commits are not scanned
- Per email: keep the **most recent** commit timestamp
- Sorted by email for stable JSON
- Non-git or empty repo: empty contributors, no error
- `EmitOptions.RepoPath` is the default git root; set `BillingItem.RepoPath` to override per project when a single POST spans multiple directories
- Git collection failures are surfaced on `Result.ContributorCollectionErr` while the POST still proceeds with empty contributors for affected items

Semantics align with:

- `snyk/cli` → `src/lib/monitor/dev-count-analysis.ts` (`getContributors`)
- `cli-extension-iac` → `internal/git/contributors.go` (`ListContributors`)

`ListContributors` is exported for callers that need contributor data without emitting.

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
| `skipped` | `missing_target_id` | All items missing `target_id` |
| `skipped` | `missing_capability` | `Capability` is empty |
| `skipped` | `missing_scope_id` | `ScopeID` is empty |
| `failed` | `marshal_error` | Ingest payload could not be marshaled |
| `failed` | `missing_ingest_url` | `IngestURL` is empty |
| `failed` | `request_error` | HTTP request could not be constructed |
| `failed` | `http_error` | Network error or non-202 response (`Result.Err` set for unexpected status) |
| `failed` | `timeout` | POST exceeded `Timeout` (default 5s) |
| `failed` | `canceled` | Parent context canceled before POST completed |
| `emitted` | — | HTTP 202; check `ContributorCollectionErr` if git collection failed |

Items with empty `target_id` are dropped; remaining valid items are still emitted.

## Future call sites (out of scope for this package)

| Repo | When | Capability | Target ID source |
|------|------|------------|------------------|
| cli-extension-os-flows | Dragonfly monitor success | `oss` | monitor response `target_id` |
| cli-extension-iac | ShareResultsRegistry (Path B) | `iac` | share response `target_id` |
| code-client-go | Native `--report` success | `code` | `ResultMetaData.TargetId` |

Not in scope: IaC Path C (cloud upload), SCLE Code `--report`, container/docker monitor.

## Out of scope

- Retries, compression, rate limiting
- ES ingest implementation / Kafka
- Wiring into extension repos
