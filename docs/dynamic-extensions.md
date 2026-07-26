# Dynamic extensions

A dynamic extension is a **standalone binary** that adds commands to a CLI built
on this framework — loaded at runtime, without rebuilding the CLI. It runs as a
separate process, so you can build and iterate on it on its own, and a bug in it
can't crash the host.

Inside your extension, a command looks exactly like a built-in one: it's an
ordinary `workflow.Callback`. The fact that it lives in another process is
handled for you.

## Try the example

```bash
make build-examples          # builds examples into .bin/
```

This produces `.bin/whoami`, an extension that adds an `example.whoami` command
which calls the host's built-in `whoami`. To load it, point a host app at the
binary:

```go
engine := app.CreateAppEngineWithOptions(
    app.WithConfiguration(config),
    app.WithExtensionPaths("./.bin/whoami"),
)
```

On a CLI that wires it up, the same thing is available as a `--plugin-path`
flag (or the `SNYK_INTERNAL_EXTENSION_PATHS` environment variable).

## Write your own

An extension's `main` registers its commands and hands them to `extension.Serve`:

```go
package main

import (
    "github.com/snyk/go-application-framework/pkg/extension"
    "github.com/snyk/go-application-framework/pkg/workflow"
)

func main() {
    extension.Serve(func(r extension.Registrar) {
        r.Register("flw://hello", hello)
    })
}

func hello(ictx workflow.InvocationContext, _ []workflow.Data) ([]workflow.Data, error) {
    id := workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("hello"), "greeting")
    name := ictx.GetConfiguration().GetString("name")
    return []workflow.Data{workflow.NewData(id, "text/plain", []byte("hello "+name))}, nil
}
```

Build it (`go build -o ./.bin/hello ./path/to/ext`) and load it the same way as
the example. Change the code, rebuild the binary, run again — no CLI rebuild.

## What an extension can do

Through the `InvocationContext` passed to each command, an extension can:

- **Read configuration** — flags it declares (`extension.WithFlags`) and settings
  the host resolves, via `ictx.GetConfiguration()`.
- **Call the Snyk API** — `ictx.GetNetworkAccess().GetHttpClient()` gives an HTTP
  client that the host authenticates for you. Your credentials stay in the host
  process; the extension never sees them.
- **Call other workflows** — `ictx.GetEngine().Invoke(id, ...)` runs another
  workflow (built-in or from another extension) on the host, in its full
  context. The `whoami` example does exactly this.
- **Record analytics** — `ictx.GetAnalytics().AddExtension*Value(...)` feeds into
  the host's usual analytics.

## Good to know

- **Bundled commands win.** If your extension registers a command that already
  exists, it's skipped by default (so an extension can't silently replace a
  built-in). Set `internal_extension_allow_override=true` to opt in.
- **Trusted extensions for now.** Extensions run with your normal user
  permissions — this is aimed at local development and trusted binaries, not
  sandboxing untrusted third-party code (that's a later phase).
- **Two full examples** live in the repo: `examples/extensions/whoami` (minimal,
  calls a host workflow) and `pkg/extension/testdata/exampleplugin` (config, an
  authenticated API call, and calling another workflow + analytics).

## How it works

If you want the internals — the gRPC protocol, the loopback auth proxy, the
host-callback channel — see the [design doc](./dynamic-extensions-design.md) and
the [architecture diagrams](./dynamic-extensions-architecture.md).
