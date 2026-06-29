# Dynamic Extensions — Technical Design

> Diagrams: see [dynamic-extensions-architecture.md](./dynamic-extensions-architecture.md)
> for a component view (existing vs. new) and an invocation sequence diagram.

Status: **Developer loop + authenticated network + host callbacks.** Implemented
in `pkg/extension`. Extensions load from prebuilt binaries without rebuilding the
host, run out of process over gRPC, receive a full `workflow.InvocationContext`,
call the Snyk API using the host's credentials without ever holding them, invoke
sibling workflows on the host engine, and record analytics into the host's
batch.

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

**Also delivered (host callbacks)**

- Authenticated network access via the "option C" loopback auth proxy (§5a), so
  trusted extensions can call the Snyk API with the user's credentials kept
  host-side.
- Sibling workflow invocation (`GetEngine().Invoke`) and analytics recording,
  bridged back to the host over the go-plugin broker (§5b).

**Non-goals (deferred — see §10)**

- Downloading/installing extensions, a registry, signature verification, or an
  enterprise allowlist.
- Bridging the remaining host services as live callbacks: `UserInterface`
  (interactive prompts/progress) and `RuntimeInfo` are local/unavailable for now.
- A sandbox that constrains a *malicious* extension. The current phase isolates
  for robustness (crash containment), not for confinement; an extension binary
  runs with the user's OS privileges. Confinement is a trust-layer + (optionally
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

## 5a. Authenticated network access — "option C" (`authproxy.go`)

Extensions need to call the Snyk API with the user's authentication, proxy, and
TLS configuration. Rather than ship credentials into the extension process, the
host runs a **loopback authenticating reverse proxy** for the duration of each
invocation:

```
extension http.Client ──plain HTTP──▶ 127.0.0.1:PORT (AuthProxy)
                                          │  validate per-invocation secret
                                          │  strip secret, rewrite onto API_URL
                                          ▼
                                   host authenticated RoundTripper ──HTTPS──▶ Snyk API
                                   (injects auth + headers + proxy + TLS)
```

- The host passes the extension two strings in `ExecuteRequest`: the proxy
  `BaseURL` and a per-invocation random secret. **Credentials never cross into
  the extension process.**
- On the plugin side the proxy URL is installed as the extension's
  `configuration.API_URL`, and the secret is attached as a static header
  (`buildNetworkAccess`). Extension code calls `GetNetworkAccess().GetHttpClient()`
  and builds URLs from `API_URL` exactly as an in-process workflow does.
- The proxy's transport is `invocation.GetNetworkAccess().GetRoundTripper()`, so
  the host injects auth precisely as if it had made the call itself.
- The secret check (constant-time) ensures other local processes can't use the
  proxy. The proxy is scoped to the single configured upstream (the API); it is
  **not** a general-purpose egress. The whole proxy lives only for the duration
  of the `Execute` call.

This needs no gRPC broker: the extension reaches the loopback proxy over an
ordinary socket, so the large `NetworkAccess` interface is never marshaled.

**Scope — what this restricts.** The proxy rewrites every request onto the one
configured upstream (`API_URL`), so the host-injected credentials can only ever
reach the Snyk API — an extension cannot point them at another host. It does
**not** sandbox the extension's own outbound sockets: the process can still open
its own unauthenticated connections anywhere (we are not confining the process
in this phase). The restriction is specifically on where the *host's
credentials* can go, and the proxy is the single point where a future policy can
log, scope, or deny that egress per extension.

## 5b. Host callbacks — sibling workflows & analytics (`hostcallback.go`, `proxies.go`)

Some services must call *back* into live host objects, so for these the host
stands up a second gRPC service — `HostCallback` — that the extension dials over
go-plugin's `GRPCBroker` (bidirectional channel). This is set up per invocation:

1. Before calling `Execute`, the host picks a broker id, starts
   `broker.AcceptAndServe(id, …)` serving a `hostCallbackServer` bound to *this
   invocation's* engine and analytics, and passes the id in `ExecuteRequest`.
2. The extension dials the id (`broker.Dial`) and builds a `HostCallback`
   client, which backs a `remoteEngine` and `remoteAnalytics` on the plugin
   side. It always dials when an id is present (even if unused) so the host's
   serving goroutine terminates; the connection closes when `Execute` returns.

What crosses:

- **`GetEngine().Invoke(id, …)`** → `HostCallback.Invoke`. The host runs the
  sibling workflow **in its own full context** (auth, network, other
  extensions). This is the key architectural point: extensions and built-ins
  compose the same way in-process workflows do — by **identifier through the
  engine's public `Invoke`**, never by calling each other's code. Because
  `EngineInvokeOption`s are opaque closures, the plugin resolves the caller's
  input via `workflow.ResolveInvokeOptions`; per-invocation config overrides are
  not propagated across the boundary in this phase (the sibling uses the host's
  configuration).
- **`GetAnalytics()` recording** (`AddExtension*Value`, `AddError`) →
  `HostCallback.AddExtensionValue`/`ReportError`, landing on the invocation's
  host analytics (prefixed by the calling workflow id, e.g.
  `hello.callsibling::ext.example`) so it ships in the host's batch.

`remoteAnalytics` embeds a local `analytics.Analytics` to satisfy the full
interface and overrides only the recording methods; `remoteEngine` implements
`workflow.Engine` with `Invoke`/`InvokeWith*` forwarding and host-only methods
as no-ops/errors.

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
  starts the loopback auth proxy (§5a), marshals input, calls `Execute`, and
  converts the result back to `[]workflow.Data`.
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

func greet(ictx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
    id := workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("hello"), "greeting")
    name := ictx.GetConfiguration().GetString("name")
    return []workflow.Data{workflow.NewData(id, "text/plain", []byte("hello "+name))}, nil
}
```

`extension.Handler` is a type alias for `workflow.Callback` — an extension
handler *is* a workflow callback, so an existing in-process workflow can be
served as an extension without changing its signature.

On the plugin side, `Serve` builds a real `workflow.InvocationContext`
(`invocationcontext.go`) and passes it to the handler. Which services are live:

| Service | Status in this phase |
|---|---|
| `GetConfiguration()` | declared flags + the proxied `API_URL` |
| `GetNetworkAccess()` | **live** — routed through the host auth proxy (§5a) |
| `GetEngine().Invoke(...)` | **live** — runs sibling workflows on the host (§5b) |
| `GetAnalytics()` | **live** — instrumentation flows into the host's batch (§5b) |
| `GetLogger()` / `GetEnhancedLogger()` | write to stderr (go-plugin forwards to host) |
| `GetUserInterface()` | console UI on **stderr** (stdout is the plugin protocol channel) |
| `GetRuntimeInfo()` | `nil` — not yet bridged |

The remaining `Engine` methods on the extension-side engine (`Register`, `Init`,
the `Set*`/`Get*Workflow*` family) are host-only concerns and are no-ops or
return errors across the boundary.

The full working example (a config workflow **and** an authenticated API call) is
`pkg/extension/testdata/exampleplugin`.

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

What this phase *does* provide:

- **Isolation for robustness.** Extensions run in their own process; a crash is
  contained. The host never executes extension code in-process (contrast Go's
  native `plugin` package, which we explicitly rejected: no Windows support,
  exact-toolchain coupling, zero isolation).
- **Handshake gating.** The magic cookie + protocol version stop a stray or
  mismatched executable from being driven as an extension.
- **Minimal config exposure.** Only declared keys are exported to an extension.
- **Credentials stay host-side.** Network access uses the option-C auth proxy
  (§5a): the host injects authentication; the extension only ever holds a
  short-lived, single-upstream loopback secret. The host mediates every outbound
  request, which is also the seam where a future allowlist can scope or deny
  egress per extension.
- **Explicit, operator-controlled loading.** Nothing is auto-discovered or
  auto-downloaded.

What this phase deliberately does **not** provide (and must not be mistaken for):

- It is **not** a sandbox. A loaded binary runs with the user's full OS
  privileges. It assumes the operator chose to run the binary — appropriate for
  local development and trusted extensions, **not** for untrusted third-party
  code.

The enterprise-safety properties — verifying *which* code may run — live in the
trust layer (§10), mirroring how Terraform secures providers (signing +
registry + the org choosing what to install) rather than sandboxing them.

## 10. Roadmap and the seams left for it

- **Remaining host callbacks.** Network (§5a), sibling `Engine.Invoke`, and
  analytics (§5b) are done. Still local-only: `UserInterface` (interactive
  prompts/progress need streaming RPCs) and `RuntimeInfo`. Seam:
  `pluginInvocationContext` is the single place these are assembled on the plugin
  side, and `HostCallback` is the service to extend.
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
- **`authproxy_test.go`** — secret enforcement (constant-time, rejects
  missing/wrong) and host-side auth injection, against a fake upstream.
- **`callbacks_test.go`** — `hostCallbackServer` + `remoteEngine`/
  `remoteAnalytics` over a real in-memory gRPC connection: sibling invoke and
  analytics forwarding, no subprocess.
- **`loader_e2e_test.go`** and **`app/app_extension_test.go`** — the subprocess
  proofs (skipped under `-short`): load-without-rebuild; the **option-C proof**
  (extension makes an authenticated API call, host injects the token); and the
  **host-callback proof** (extension invokes a host sibling workflow and records
  analytics over the broker).

## 12. File map

| File | Responsibility |
|------|----------------|
| `proto/extension.proto` | gRPC service + message definitions |
| `proto/*.pb.go` | generated code (`buf generate`) |
| `plugin.go` | handshake, go-plugin adapters (broker capture), host `grpcClient`, `pluginConn` |
| `convert.go` | `Data`/payload/config marshaling |
| `authproxy.go` | host-side loopback auth proxy (option C) |
| `hostcallback.go` | host-side `HostCallback` server (sibling invoke, analytics) |
| `proxies.go` | plugin-side `remoteEngine` + `remoteAnalytics` |
| `serve.go` | plugin-author SDK (`Serve`, `Registrar`) + `serveHandler` |
| `invocationcontext.go` | plugin-side `workflow.InvocationContext` |
| `loader.go` | host-side `Loader` (`ExtensionInit`), proxy, real dialer |
| `testdata/exampleplugin` | reference extension (config, API call, sibling invoke + analytics) |
| `workflow/engineimpl.go` | `ResolveInvokeOptions` helper |
| `app/app.go`, `app/options.go` | `WithExtensionPaths` + factory wiring |
