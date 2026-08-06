# Entitlements Service Contributor Ingest API Client

Generated client for posting CLI Active Contributor billing events to
entitlements-service.

## Intent

Provide typed API-level interactions with the Contributing Devs ingest endpoint
instead of hand-rolled HTTP in consumers such as `internal/contributorbilling`.

## Directory contents

- `2026-07-29/spec.yaml`: Vendored OpenAPI from entitlements-service
  `contributingDevsIngestApi` (2024-10-15).
- `2026-07-29/spec.config.yaml`: oapi-codegen configuration.
- `2026-07-29/gen.go`: `go:generate` entry point.
- `2026-07-29/entitlements_service.go`: Generated models and client.
- `client.go`: Thin wrapper used by `internal/contributorbilling`.

## Usage

```go
client, err := entitlements_service.NewIngestClient(httpClient, "https://api.snyk.io")
resp, err := client.CreateContributingDevs(ctx, orgID, authHeader, request)
```

`ingestURL` must include scheme and host; an optional path prefix is preserved when passed directly to `NewIngestClient`.

## Updating the spec

When entitlements-service changes the ingest OpenAPI, update `2026-07-29/spec.yaml`
(or add a new version directory), then run `make generate`.
