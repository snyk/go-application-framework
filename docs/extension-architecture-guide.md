# Extension Architecture Guide

How to architect an extension for the go-application-framework (GAF),
covering separation of concerns, self-descriptive APIs, and idiomatic Go
practices.

---

## Core Concepts

### Design Goal: Self-Descriptive APIs

The framework aims for **self-descriptive** functional units. A workflow
describes itself — its name, parameters, types, usage text, and annotations.
The data it produces describes itself via content types and metadata headers.

A generic consumer can:

- **Discover** all workflows via `engine.GetWorkflows()`.
- **Inspect** parameters via `entry.GetConfigurationOptions()`.
- **Invoke** any workflow uniformly via `engine.Invoke(id, ...)`.
- **Route** output by content type, not by knowledge of which workflow
  produced it.

Today this enables CLI commands auto-generated from identifiers and flag sets,
help text derived from usage strings, and output routing by content type. As
the system matures, the same metadata will drive IDE configuration UIs, MCP
tool definitions, and integration in other applications — all without
per-workflow glue code.

**Invest in describing your workflow well at registration time.** The richer
the metadata, the more automatically it integrates across surfaces.

### Engine

`workflow.Engine` is a registry, runtime, and **discovery API** for workflows.
It owns shared infrastructure — configuration, networking, analytics, logging,
UI — and exposes them to workflows through an `InvocationContext`. Any consumer
(CLI, IDE, MCP server) can enumerate and introspect registered workflows
without knowing them in advance.

### Workflows

A named function registered with the engine. It receives platform services via
`InvocationContext` and typed `[]Data` input, and returns `[]Data` output plus
an error.

```go
type Callback func(invocation InvocationContext, input []Data) ([]Data, error)
```

The **identifier** is a URL encoding the command hierarchy:
`workflow.NewWorkflowIdentifier("code.test")` → `flw://code.test` → CLI
command `snyk code test`. The identifier *is* the command definition.

**Visibility** (`entry.SetVisibility(false)`) controls auto-generated command
listings. Internal workflows (output, analytics) hide themselves.

### Data

`workflow.Data` is a content-negotiated envelope carrying a **payload**
(`[]byte`), a **content type** (MIME-like), **metadata headers**, a **content
location**, and an **error list**.

Because data describes itself, consumers route by content type generically:

| Content type | Downstream behavior |
|---|---|
| `application/json; schema=local-finding-summary` | Severity filtering, findings rendering |
| `application/json; schema=test-summary` | Summary rendering |
| `application/sarif+json` | SARIF file output, IDE integration |
| `application/json` | Generic JSON output |
| `text/plain` | Plain text output |

The producer labels its output; consumers route by label — no per-workflow
`switch` needed.

### ExtensionInit

Registers one or more workflows plus configuration defaults during
`engine.Init()`:

```go
type ExtensionInit func(engine Engine) error
```

---

## Architectural Principles

### The Microservice Analogy

| Microservice concept | GAF equivalent |
|---|---|
| A **service** | An **extension** (`ExtensionInit` + its package) |
| An **endpoint** (route + handler) | A **workflow** (identifier + callback) |
| Request/response DTOs | `workflow.Data` (content-negotiated envelopes) |
| The HTTP framework | The **engine** (config, networking, analytics, UI) |

Just as a microservice keeps HTTP handlers thin — parse request, call domain
logic, serialize response — an extension keeps workflow callbacks thin and
pushes business logic into domain packages.

**What should the service expose?** That depends on the business logic. An
extension may register one workflow (`code.test`) or a cohort
(`ignore.create` / `ignore.edit` / `ignore.delete`). The boundary matches a
bounded context: cohesive operations over a shared domain, with a clear API
surface and internal details hidden behind it.

### 1. The Workflow Is a Thin Integration Shell

> **A workflow callback should be an orchestrator, not the implementation.**

1. Extract platform services from `InvocationContext`.
2. Read configuration values.
3. Call **business logic** (pure functions, domain types, service clients).
4. Package the result into `[]Data` and return.

If domain logic takes `InvocationContext` as a parameter, it becomes coupled to
the framework and hard to test.

```go
// Good: business logic has no GAF dependency
func RunAnalysis(ctx context.Context, client *http.Client, path string) (*Result, error) { ... }

func entryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
    ctx    := invocationCtx.Context()
    config := invocationCtx.GetConfiguration()
    client := invocationCtx.GetNetworkAccess().GetHttpClient()

    result, err := RunAnalysis(ctx, client, config.GetString(configuration.INPUT_DIRECTORY))
    if err != nil {
        return nil, fmt.Errorf("analysis failed: %w", err)
    }

    bytes, _ := json.Marshal(result)
    data := workflow.NewData(
        workflow.NewTypeIdentifier(WORKFLOWID, "result"), "application/json", bytes,
        workflow.WithConfiguration(config), workflow.WithLogger(invocationCtx.GetEnhancedLogger()),
    )
    return []workflow.Data{data}, nil
}
```

```go
// Bad: domain code coupled to GAF
func RunAnalysis(invocationCtx workflow.InvocationContext) (*Result, error) { ... }
```

### 2. Structure: Init ↔ EntryPoint ↔ Domain

```
extension/
├── init.go           # ExtensionInit + Register + config defaults
├── workflow.go       # Callback (thin shell)
└── domain/           # Business logic, clients, types (no GAF imports)
```

- **`init.go`** — Identifier, flag set, `engine.Register`, `AddDefaultValue`.
  The *only* file importing `workflow.Engine`.
- **`workflow.go`** — Callback: extract services, call domain, wrap results.
- **`domain/`** — Pure logic accepting concrete types (`context.Context`,
  `*http.Client`, config values). No `workflow.*` imports.

### 3. Registration: Focused and Descriptive

Keep `ExtensionInit` fast and deterministic. Treat it as where the workflow
**describes itself** to the platform:

```go
func Init(engine workflow.Engine) error {
    flags := pflag.NewFlagSet("myext.test", pflag.ExitOnError)
    flags.String("target-file", "", "Path to target file")
    flags.Bool("json", false, "Output in JSON format")

    _, err := engine.Register(WORKFLOWID, workflow.ConfigurationOptionsFromFlagset(flags), entryPoint)
    if err != nil {
        return err
    }

    engine.GetConfiguration().AddDefaultValue(configKeySetting, getSettingDefault(engine))
    return nil
}
```

- Register **one workflow** per Init unless tightly related.
- **Write meaningful usage strings** — they become CLI help today, IDE tooltips
  and MCP descriptions tomorrow.
- Use `AddDefaultValue` for lazily-resolved values (API calls, feature flags).
- Use `AddKeyDependency` when one key's default depends on another.
- Use `internal_` prefix for non-user-facing configuration keys.

### 4. Testability

For complex workflows, split construction from logic:

```go
func entryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) (_ []workflow.Data, err error) {
    authenticator := auth.NewOAuth2Authenticator(invocationCtx.GetConfiguration(), ...)
    return nil, doAuth(invocationCtx.GetEnhancedLogger(), authenticator)  // testable
}
```

`doAuth` accepts concrete interfaces that are easy to mock. For simple
workflows, a direct call to domain code from the callback is sufficient.

---

## Composing Workflows

Workflows can invoke other workflows through the engine:

```go
whoamiConfig := config.Clone()
whoamiConfig.Set(configuration.FLAG_EXPERIMENTAL, true)
data, err := invocationCtx.GetEngine().InvokeWithConfig(WORKFLOWID_WHOAMI, whoamiConfig)
```

- **Clone config** before passing to avoid mutating caller state.
- Prefer `engine.Invoke()` with functional options (`WithConfig`, `WithInput`,
  `WithContext`) over deprecated methods.
- Keep cross-workflow calls shallow — deep chains create implicit coupling.

---

## Error Handling

**Wrap errors** with context using `%w` to preserve the chain for
`errors.Is`/`errors.As`:

```go
result, err := apiClient.Fetch(ctx)
if err != nil {
    return nil, fmt.Errorf("fetching scan results: %w", err)
}
```

**Use error-catalog errors** for user-facing problems — they carry structured
titles, classifications, and messages the output layer renders correctly:

```go
return nil, code.NewFeatureIsNotEnabledError(
    fmt.Sprintf("Snyk Code is not supported for org: %s", orgSlug),
)
```

**Return error vs. attach to Data:**
- **Return** when the workflow can't produce meaningful output — the pipeline
  stops.
- **`data.AddError(...)`** when you have partial results but want to signal
  warnings.

**Check errors immediately and return early.** Avoid accumulating errors unless
explicitly aggregating them with `errors.Join`.

---

## Anti-Patterns

- **❌ Domain logic inside the callback** — Extract into domain packages.
- **❌ Passing `InvocationContext` into domain code** — Pass concrete values
  (`context.Context`, `*http.Client`, config strings) instead.
- **❌ Deep workflow call chains** — Keep composition flat; let callers
  orchestrate pipelines.
- **❌ Mutating global configuration from a workflow** — The engine clones
  config per invocation; mutations don't propagate back.
- **❌ Ignoring content types** — Consumers route data by content type.
  Incorrect types break downstream processing.

---

## Complete Template

```go
package myext

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"

    "github.com/spf13/pflag"
    "github.com/snyk/go-application-framework/pkg/configuration"
    "github.com/snyk/go-application-framework/pkg/workflow"
)

const workflowName = "myext.test"

var WORKFLOWID = workflow.NewWorkflowIdentifier(workflowName)

func Init(engine workflow.Engine) error {
    flags := pflag.NewFlagSet(workflowName, pflag.ExitOnError)
    flags.Bool("json", false, "Output in JSON format")
    _, err := engine.Register(WORKFLOWID, workflow.ConfigurationOptionsFromFlagset(flags), entryPoint)
    return err
}

func entryPoint(invocationCtx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
    config := invocationCtx.GetConfiguration()
    logger := invocationCtx.GetEnhancedLogger()

    result, err := analyze(invocationCtx.Context(), invocationCtx.GetNetworkAccess().GetHttpClient(),
        config.GetString(configuration.API_URL), config.GetString(configuration.INPUT_DIRECTORY))
    if err != nil {
        return nil, fmt.Errorf("analysis failed: %w", err)
    }

    bytes, err := json.Marshal(result)
    if err != nil {
        return nil, fmt.Errorf("marshal result: %w", err)
    }

    data := workflow.NewData(
        workflow.NewTypeIdentifier(WORKFLOWID, workflowName), "application/json", bytes,
        workflow.WithConfiguration(config), workflow.WithLogger(logger),
    )
    return []workflow.Data{data}, nil
}

func analyze(ctx context.Context, client *http.Client, apiURL, path string) (*MyResult, error) {
    return &MyResult{}, nil // domain logic here
}

type MyResult struct{}
```

Register in the host application:

```go
engine.AddExtensionInitializer(myext.Init)
```

---

## Summary

| Concern | Where it lives |
|---|---|
| Registration, flags, config defaults | `Init` function (`ExtensionInit`) |
| Platform wiring, data packaging | Workflow callback (thin shell) |
| Business logic, API clients, transforms | Domain packages (no GAF imports) |
| Error surfacing to users | error-catalog types + `fmt.Errorf` wrapping |

---

## Further Reading

### Architecture & Design Patterns

- **IOSP (Integration Operation Segregation Principle)** — Functions should be
  either *integrations* (composing calls) or *operations* (performing logic),
  not both. Directly informs the "thin callback" rule.
  - Ralf Westphal, [IOSP](https://ralfwestphal.substack.com/p/integration-operation-segregation) · [IOSP 2.0](https://ralfwestphal.substack.com/p/iosp-20)

- **Hexagonal Architecture (Ports & Adapters)** — The callback is an *adapter*;
  domain code is the *core*.
  - Alistair Cockburn, [Hexagonal Architecture](https://alistair.cockburn.us/hexagonal-architecture) · [Wikipedia](https://en.wikipedia.org/wiki/Hexagonal_architecture_(software))

- **Microkernel / Plugin Architecture** — The engine-plus-extensions model is a
  form of the microkernel pattern.
  - Mark Richards, [Microkernel Architecture](https://www.oreilly.com/library/view/software-architecture-patterns/9781098134280/ch04.html) (Software Architecture Patterns, 2nd Ed.)

- **Separation of Concerns** — The foundational principle behind GAF's layered design.
  - [Wikipedia](https://en.wikipedia.org/wiki/Separation_of_concerns) (includes Dijkstra's original context)

### Go Error Handling

- [Working with Errors in Go 1.13](https://go.dev/blog/go1.13-errors) — `%w` wrapping, `errors.Is`, `errors.As`.
- [Error handling and Go](https://go.dev/blog/error-handling-and-go) — Go's error philosophy.
- [A practical guide to error handling in Go](https://www.datadoghq.com/blog/go-error-handling/) (Datadog) — Wrapping, custom types, production patterns.
