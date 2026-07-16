# Dynamic Extensions — Architecture Diagrams

These diagrams accompany [dynamic-extensions-design.md](./dynamic-extensions-design.md).

**Legend:** 🟦 blue = pre-existing architecture · 🟩 green = added by the dynamic-extensions work.

## Component view — before vs. after

Everything blue already existed: extensions were Go functions linked into the
binary at compile time and registered with the engine. Everything green is new —
it lets an extension instead be a **separate binary**, loaded at runtime and run
in its own process, while still looking like an ordinary workflow.

```mermaid
flowchart TB
    classDef existing fill:#dbeafe,stroke:#3b82f6,color:#0b1f44;
    classDef new fill:#d4f8d4,stroke:#2ea043,color:#06210d;

    subgraph HOST["Host CLI process"]
        APP["app.CreateAppEngineWithOptions"]:::existing
        ENG["workflow.Engine<br/>registry + Invoke dispatch"]:::existing
        LWF["localworkflows.Init<br/>built-in extensions (compile-time import)"]:::existing
        BW["built-in workflow callback<br/>e.g. flw://output"]:::existing
        IC["InvocationContext<br/>Config · NetworkAccess · Analytics · UI · Logger"]:::existing

        LOADER["extension.Loader<br/>(a workflow.ExtensionInit)"]:::new
        PROXY["proxy callback<br/>1 per discovered workflow"]:::new
        AP["AuthProxy<br/>loopback, option C"]:::new
        HCB["HostCallback server<br/>sibling Invoke · analytics"]:::new
    end

    subgraph EXT["Extension process — separate binary (subprocess)"]
        SERVE["extension.Serve"]:::new
        EH["Handler = workflow.Callback"]:::new
        PIC["plugin InvocationContext<br/>remoteEngine · remoteAnalytics · NetworkAccess"]:::new
    end

    API["Snyk API"]:::existing

    APP --> ENG
    APP --> LWF
    LWF -. "AddExtensionInitializer / Register" .-> ENG
    ENG --> BW
    BW --> IC

    APP --> LOADER
    LOADER -. "launch + Discover, then Register proxy" .-> ENG
    ENG -->|"Invoke(id)"| PROXY
    PROXY -->|"gRPC: Execute<br/>(config snapshot, input,<br/>proxy URL+secret, broker id)"| SERVE
    SERVE --> EH --> PIC

    PIC -->|"plain HTTP + secret"| AP
    AP -->|"authenticated HTTPS<br/>(host injects credentials)"| API

    PIC -->|"gRPC broker (bidirectional)"| HCB
    HCB -->|"Engine.Invoke(sibling)"| ENG
    HCB -->|"record"| IC
```

Key idea: the green path is a faithful reflection of the blue one across a
process boundary. A built-in workflow is reached by `Engine.Invoke(id)` → its
callback gets an `InvocationContext`. A dynamic extension is reached by
`Engine.Invoke(id)` → a **proxy** callback → gRPC `Execute` → the extension's
handler gets a **reconstructed** `InvocationContext` whose network/engine/
analytics call back into the host.

## Sequence — one extension invocation

Blue band = the pre-existing dispatch shape; green band = the new
cross-process interactions (network via the auth proxy, sibling invoke and
analytics via the broker).

```mermaid
sequenceDiagram
    autonumber
    participant U as CLI command
    participant E as Engine (host)
    participant P as proxy callback (host)
    participant AP as AuthProxy (host)
    participant H as HostCallback (host)
    participant X as Extension process
    participant API as Snyk API

    rect rgb(219,234,254)
        U->>E: Invoke(flw://my-ext)
        E->>P: callback(InvocationContext, input)
    end

    rect rgb(212,248,212)
        Note over P,X: added by this work
        P->>AP: start loopback auth proxy (option C)
        P->>H: serve HostCallback on a broker id
        P->>X: gRPC Execute(config snapshot, input, proxy URL+secret, broker id)
        X->>X: build InvocationContext<br/>(remoteEngine, remoteAnalytics, NetworkAccess)

        opt extension calls the Snyk API
            X->>AP: HTTP GET {API_URL}/... (+ secret header)
            AP->>API: authenticated HTTPS (host injects token)
            API-->>AP: response
            AP-->>X: response
        end

        opt extension invokes a sibling / records analytics
            X->>H: Invoke(flw://sibling) · AddExtensionValue
            H->>E: Engine.Invoke(sibling) in host context
            E-->>H: sibling output
            H-->>X: output · ack
        end

        X-->>P: Execute response (output Data)
    end

    rect rgb(219,234,254)
        P-->>E: []Data
        E-->>U: result
    end
```

## What did NOT change

- The `workflow.Engine`, `Register`/`Invoke`, `InvocationContext`, and
  content-typed `Data` contracts are untouched — extensions plug into the exact
  same seams as built-ins.
- Built-in (compile-time) extensions still work exactly as before; the loader is
  added only when extension paths are configured.
- The only core addition is `workflow.ResolveInvokeOptions`, a helper that lets
  an `Invoke` be forwarded across the process boundary.
