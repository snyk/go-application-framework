# Entitlements Service Contributor Ingest API Client

Generated client for posting CLI Active Contributor billing events to
entitlements-service.

## Intent

Provide typed API-level interactions with the contributor ingest endpoint instead
of hand-rolled HTTP in consumers such as `pkg/contributorbilling`.

## Directory contents

- `2026-07-29/spec.yaml`: Draft OpenAPI for the ingest endpoint (placeholder until
  the official entitlements-service spec is vendored).
- `2026-07-29/spec.config.yaml`: oapi-codegen configuration.
- `2026-07-29/gen.go`: `go:generate` entry point.
- `2026-07-29/entitlements_service.go`: Generated models and client.
- `client.go`: Thin wrapper used by `pkg/contributorbilling`.

## Usage

```go
client, err := entitlements_service.NewIngestClient(httpClient, ingestURL)
resp, err := client.IngestContributors(ctx, authHeader, request)
```

`ingestURL` may be `https://api.snyk.io` or the full URL including `IngestPath`.

## Updating the spec

When the official OpenAPI is available, replace `2026-07-29/spec.yaml` (or add a
new version directory), then run `make generate`.
