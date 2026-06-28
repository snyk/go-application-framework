# Dynamic Extensions (Phase 1) — Technical Design

Status: **Phase 1 — developer loop.** Implemented in `pkg/extension`.

This document describes how the go-application-framework loads extensions
*dynamically* — from standalone binaries discovered at runtime — instead of only
at compile time. It is written to be read alongside the code; every section maps
to a file in `pkg/extension`.

## 1. Goals and non-goals

**Goals (Phase 1)**

- Load an extension from a prebuilt binary **without recompiling the host CLI**,
  so an extension can be developed and iterated on in isolation.
- Keep the workflow programming model: an extension author writes something that
  looks like a `workflow.Callback`, and it is invoked like any built-in
  workflow.
- Run extension code **out of process**, so a crash or panic in an extension
  cannot take down the host.
- Lay a wire protocol and host/plugin split that the Phase 2 trust layer
  (signing, registry, allowlist) and richer host callbacks can build on without
  re-architecting.

**Non-goals (deferred to Phase 2 — see §10)**

- Downloading/installing extensions, a registry, signature verification, or an
  enterprise allowlist.
- Giving extensions access to the host's authenticated network stack, UI, or
  analytics (host callbacks).
- A sandbox that constrains a *malicious* extension. Phase 1 isolates for
  robustness (crash containment), not for confinement; an extension binary runs
  with the user's OS privileges. Confinement is a trust-layer + (optionally
  WebAssembly) concern, called out in §9.

## 2. Background: the existing model

Today an extension is a Go function registered at compile time:

```go
type ExtensionInit func(engine Engine) error
```

`app.CreateAppEngineWithOptions` calls `engine.AddExtensionInitializer(localworkflows.Init)`,
and `engine.Init()` runs every initializer; each calls `engine.Register(id, configOptions, callback)`.
Adding an extension means importing it and rebuilding. `engineimpl.go` even
carried a `// later scan here for extension binaries` placeholder. This design
fills that gap.

## 3. Architecture overview

The host launches each extension as a child process and talks to it over gRPC,
using [`hashicorp/go-plugin`](https://github.com/hashicorp/go-plugin) — the same
mechanism Terraform and Vault use for providers/plugins.

```
┌──────────────────────── host CLI process ────────────────────────┐
│ workflow.Engine                                                   │
│   └── extension.Loader.Init  (a workflow.ExtensionInit)           │
│         │  for each configured binary:                            │
│         │    1. launch + handshake (go-plugin)                    │
│         │    2. Discover() ─────────────────────┐                 │
│         │    3. engine.Register(proxy) per spec  │                 │
│         └── proxy workflow.Callback              │                 │
│               │ on Invoke: snapshot config,      │ gRPC            │
│               │ marshal input, Execute() ────────┼────┐            │
└───────────────┼──────────────────────────────────────┼────────────┘
                │                                  │     │
┌───────────────┼── extension binary process ─────┼─────▼────────────┐
│ extension.Serve(register)                        │                  │
│   serveHandler (gRPC ExtensionServer)            │                  │
│     Discover → declared workflows + flags ───────┘                  │
│     Execute  → rebuild config, decode input, run Handler, encode    │
└─────────────────────────────────────────────────────────────────────┘
```

The process boundary is the only boundary: **no extension code is loaded into
the host's address space.**

## 4. The wire protocol

`pkg/extension/proto/extension.proto` defines a single gRPC service. Go code is
generated with `buf generate` (config in the same directory); no `protoc`
install is required.

```proto
service Extension {
  rpc Discover(DiscoverRequest) returns (DiscoverResponse); // list workflows
  rpc Execute(ExecuteRequest)   returns (ExecuteResponse);  // run one workflow
}
```

- **`Discover`** is called once after launch. It returns a `WorkflowSpec` per
  workflow: identifier, visibility, and flag specs. The host turns each into an
  `engine.Register` call, so discovered workflows are indistinguishable from
  built-ins to the rest of the engine.
- **`Execute`** carries the workflow identifier, a **config snapshot**
  (`map<string,string>`), and the input `DataMsg`s; it returns output
  `DataMsg`s.

Versioning is handled two ways: the go-plugin **handshake** (`SNYK_CLI_EXTENSION`
magic cookie + protocol version) rejects incompatible binaries before any call,
and the protobuf schema evolves additively for finer-grained changes.

## 5. Data and configuration marshaling (`convert.go`)

`workflow.Data` ↔ `DataMsg`:

- **Payload** is transported as bytes with an explicit `PayloadEncoding`
  (`BYTES`, `STRING`, `JSON`, or unspecified for nil). `[]byte` and `string` go
  verbatim; anything else is JSON-encoded and decoded back into a generic value.
- **Metadata**: `workflow.Data` exposes no way to enumerate arbitrary headers,
  only `GetContentType`/`GetContentLocation`. Those two keys cross the boundary;
  the `metadata` map is left open for additional well-known keys later.
- **Identifier**: scheme/host/path round-trip exactly. The fragment is an
  internal correlation id that `workflow.NewData` regenerates on construction,
  so it is intentionally *not* stable across the boundary.

**Config snapshot:** the host exports **only the configuration keys the workflow
declared** via its flags — not the whole configuration. At `Execute` time the
proxy reads each declared flag from the live (possibly cloned) config and sends
`name → GetString(name)`. The plugin rebuilds a `configuration.Configuration`
from its declared flag set (for defaults/types) overlaid with the snapshot. This
keeps the exported surface minimal and predictable, which also matters for the
Phase 2 security story.

## 6. Host loader (`loader.go`)

`extension.Loader.Init` *is* a `workflow.ExtensionInit`, so it is added to the
engine exactly like a built-in initializer.

- **Discovery is explicit.** The Loader loads only the binary paths it is given
  (`WithPaths`); it never scans directories on its own.
- **Failure is non-fatal.** If a binary fails to launch, fails the handshake, or
  errors during discovery, the Loader logs a warning and skips it. A broken or
  incompatible third-party extension must never prevent the CLI from starting.
- **The proxy** (`makeProxy`) is the in-process `workflow.Callback` registered
  for each discovered workflow. On invocation it snapshots the declared config,
  marshals input, calls `Execute`, and converts the result back to
  `[]workflow.Data`.
- **Lifecycle.** `Close()` terminates every launched process; a CLI should defer
  it (or `plugin.CleanupClients()`) at shutdown. go-plugin children also detect
  parent death and exit on their own, so a missed `Close` does not orphan
  processes.

The dialer (process launch) is injected, so the Loader's registration and
proxying logic is unit-tested with an in-memory fake, while a separate test
exercises the real gRPC path (see §11).

## 7. Plugin-author SDK (`serve.go`)

An extension binary's `main` is essentially one call:

```go
func main() {
    extension.Serve(func(r extension.Registrar) {
        flags := pflag.NewFlagSet("hello", pflag.ContinueOnError)
        flags.String("name", "world", "who to greet")
        r.Register("flw://hello", greet, extension.WithFlags(flags))
    })
}

func greet(_ context.Context, config configuration.Configuration, _ []workflow.Data) ([]workflow.Data, error) {
    id := workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("hello"), "greeting")
    return []workflow.Data{workflow.NewData(id, "text/plain", []byte("hello "+config.GetString("name")))}, nil
}
```

`Handler`'s signature deliberately mirrors `workflow.Callback`, so moving logic
between an in-process workflow and an out-of-process extension is mechanical.
The full working example is `pkg/extension/testdata/exampleplugin`.

## 8. Configuration and the developer loop

Paths are read from the configuration key `extension.ConfigurationKeyPaths`
(`internal_extension_paths`). They can be set three ways:

- programmatically — `app.WithExtensionPaths("/path/to/bin")`;
- by a CLI flag a host binds to that key (the intended `--plugin-path`,
  repeatable);
- by environment/config bound to that key.

`CreateAppEngineWithOptions` reads the key and, if non-empty, adds a Loader
initializer. The developer loop becomes: `go build` your extension →
`snyk --plugin-path ./my-ext <command>` → iterate, with **no host rebuild**.

## 9. Security model

What Phase 1 *does* provide:

- **Isolation for robustness.** Extensions run in their own process; a crash is
  contained. The host never executes extension code in-process (contrast Go's
  native `plugin` package, which we explicitly rejected: no Windows support,
  exact-toolchain coupling, zero isolation).
- **Handshake gating.** The magic cookie + protocol version stop a stray or
  mismatched executable from being driven as an extension.
- **Minimal config exposure.** Only declared keys are exported to an extension.
- **Explicit, operator-controlled loading.** Nothing is auto-discovered or
  auto-downloaded.

What Phase 1 deliberately does **not** provide (and must not be mistaken for):

- It is **not** a sandbox. A loaded binary runs with the user's full OS
  privileges. Phase 1 assumes the operator chose to run the binary — appropriate
  for local development, **not** for untrusted third-party code.

The enterprise-safety properties — verifying *which* code may run — live in the
Phase 2 trust layer (§10), mirroring how Terraform secures providers (signing +
registry + the org choosing what to install) rather than sandboxing them.

## 10. Phase 2 roadmap and the seams left for it

- **Host callbacks.** Give extensions the authenticated network stack, UI, and
  analytics back over gRPC using go-plugin's `GRPCBroker` (bidirectional). Seam:
  `InvocationContext` is already the single source of these services in the
  proxy; the broker plumbing slots in there.
- **Trust layer.** Signature + checksum verification (Sigstore/cosign), a
  registry with verified publishers, and a **default-deny enterprise allowlist**
  expressed as a configuration policy (e.g. `extensions.allowed`). Seam: the
  Loader's dialer/`loadOne` is the single chokepoint where a verify-before-launch
  step is added.
- **On-demand install.** Fetch + cache binaries by identifier. Seam: discovery is
  already decoupled from registration.
- **Higher-isolation tier.** A WebAssembly (wazero) runtime for untrusted
  logic-only extensions, sharing the same `Discover`/`Execute` contract.

## 11. Testing strategy

- **`convert_test.go`** — payload/Data/config round-trips (pure, fast).
- **`plugin_test.go`** — the SDK server, host client adapter, and conversion over
  a *real* in-memory gRPC connection (`plugin.TestGRPCConn`), no subprocess.
- **`loader_test.go`** — registration, visibility, config-snapshot scoping, proxy
  invocation, and graceful skip on dialer failure, using an injected fake conn
  against a real `workflow.Engine`.
- **`loader_e2e_test.go`** and **`app/app_extension_test.go`** — the
  load-without-rebuild proof: compile the testdata binary, then load and invoke
  it through the real go-plugin subprocess dialer (skipped under `-short`).

## 12. File map

| File | Responsibility |
|------|----------------|
| `proto/extension.proto` | gRPC service + message definitions |
| `proto/*.pb.go` | generated code (`buf generate`) |
| `plugin.go` | handshake, go-plugin adapters, host `grpcClient`, `pluginConn` |
| `convert.go` | `Data`/payload/config marshaling |
| `serve.go` | plugin-author SDK (`Serve`, `Registrar`) + `serveHandler` |
| `loader.go` | host-side `Loader` (`ExtensionInit`), proxy, real dialer |
| `testdata/exampleplugin` | minimal reference extension |
| `app/app.go`, `app/options.go` | `WithExtensionPaths` + factory wiring |
