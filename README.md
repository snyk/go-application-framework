# go-application-framework

A framework to support building client-side applications like the [Snyk CLI](https://github.com/snyk/cli) as well as extensions for these applications.

## Getting started

This module is consumed as a dependency by downstream projects (e.g. the [Snyk CLI](https://github.com/snyk/cli)) via a `replace` directive in their `go.mod`. To work on it locally, point the consumer at your checkout:

```
replace github.com/snyk/go-application-framework => ../../go-application-framework
```

Then iterate with:

```bash
make test    # run the full test suite
```

Run `make help` to see all available targets.

## Key packages

| Package | Description |
|---------|-------------|
| `pkg/local_workflows/` | Workflow engine and output pipeline (SARIF, human-readable, etc.) |
| `pkg/apiclients/testapi/` | Generated API client and data types for the Snyk Test API |
| `pkg/utils/ufm/` | Unified Finding Model serialization (optimized `problemStore`/`_problemRefs` wire format) |
| `internal/presenters/` | UFM presenters — Go templates that render `TestResult` data into SARIF and human-readable output |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for extension authoring, UFM test fixture generation, and other contributor workflows.

## Security

For any security issues or concerns, see the [SECURITY.md](SECURITY.md) file in this repository.

## Development

```bash
make format      # gofmt
make lint        # golangci-lint
make generate    # regenerate mocks and API clients
make test        # unit tests with race detector
make testv       # verbose test output
```
