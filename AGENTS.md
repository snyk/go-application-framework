# AGENTS.md

Guidance for AI agents and human contributors working in the
**go-application-framework (GAF)**. Read this first; it sets the ground rules,
then points you at the deeper docs.

---

## What GAF is — and why that changes how you contribute

GAF is **a framework / shared library**, not an application. It is consumed as a
dependency by downstream projects — most notably the
[Snyk CLI](https://github.com/snyk/cli) — and it must serve **many different
kinds of consumers** at once: the CLI today, and IDE integrations, MCP servers,
and other host applications tomorrow.

That single fact drives everything below:

- **You are writing API, not app code.** Every exported symbol in `pkg/` is part
  of a contract that other teams build on. Code that would be fine inside one
  application can be a breaking change here.
- **Stability is a feature.** Downstream consumers pin to GAF via a `go.mod`
  `replace`/version. Changing or removing an exported signature, struct field,
  configuration key, content type, or workflow identifier can break them without
  warning. Treat the public surface as load-bearing.
- **Cater to multiple application types.** Don't bake in CLI-only assumptions
  (e.g. "there is a terminal", "output goes to stdout", "the user can be
  prompted"). Drive behavior through `Configuration`, `InvocationContext`, and
  content types so an IDE or server consumer can wire it differently.
- **Self-description over hard-coding.** Workflows and data describe themselves
  (identifiers, config options, content types, metadata) so generic consumers
  can discover, inspect, and route them without per-workflow glue. Invest in
  that metadata. See the architecture guide.

### Public API & stability checklist

Before changing anything under `pkg/`, ask:

- Am I changing an **exported** function/method/type/field signature? → breaking.
- Am I removing or renaming a **configuration key**, **workflow identifier**, or
  **content type**? → breaking for whoever depends on it.
- Am I changing **default behavior** that a consumer may rely on? → breaking.
- Can I make this **additive** instead (new function, new optional field, new
  functional option, new default value) and keep the old path working? → prefer
  this.
- If a break is truly unavoidable, it must be a `feat!`/`fix!` or carry a
  `BREAKING CHANGE:` footer so semantic-release bumps the major version. See
  [CONTRIBUTING.md](CONTRIBUTING.md#handling-breaking-changes).

---

## Documentation map

| Read this | When |
|---|---|
| [docs/extension-architecture-guide.md](docs/extension-architecture-guide.md) | Designing an extension/workflow — engine, workflows, `Data`, the thin-callback rule, error handling, anti-patterns, the complete template. **Start here for any feature work.** |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Step-by-step extension creation, UFM test-fixture generation/redaction, conventional commits, breaking-change handling. |
| [README.md](README.md) | Quick start, key packages, local `replace`-based development, dev commands. |
| [SECURITY.md](SECURITY.md) | Reporting security issues. |

---

## Repo structure

```
pkg/                  ← Public API surface (exported; treat as load-bearing)
  workflow/           Engine, WorkflowIdentifier, Data
  configuration/      Configuration interface
  app/                CreateAppEngine entry point
  networking/         HTTP client with auth/proxy support
  auth/               Authentication helpers
  analytics/          Analytics pipeline
  instrumentation/    Instrumentation hooks
  logging/            Structured logging
  ui/                 User-facing output (not terminal-specific)
  local_workflows/    Built-in workflows + output pipeline
  apiclients/         Generated API clients
  utils/              Utilities including UFM (Unified Finding Model)
  mocks/              Shared mock implementations
  envvars/            Environment-variable constants
  configtest/         Test helpers for Configuration
  devtools/           Developer tooling utilities
  runtimeinfo/        Runtime information helpers
internal/             ← Private implementation details (not part of the public API)
  api/                Internal API helpers
  constants/          Internal constants
  presenters/         Output formatters
  ufm_helpers/        UFM processing internals
  local_findings/     Local finding sources
  utils/              Internal utilities
  mocks/              Internal mocks
cmd/
  ufm-fixture-tool/   CLI tool for redacting UFM test fixtures
docs/                 Architecture guide and design docs
scripts/              Linting, fixture generation, API spec scripts
```

Tests live **next to their source files** (`foo.go` → `foo_test.go`).

---

## Core architectural rules (summary — full detail in the architecture guide)

1. **The workflow callback is a thin integration shell** — extract services from
   `InvocationContext`, read config, call domain logic, package `[]Data`. No
   business logic in the callback.
2. **Domain code has no GAF imports** — pass concrete types (`context.Context`,
   `*http.Client`, config values), never `InvocationContext`, into domain logic.
3. **Structure:** `init.go` (register + config defaults) ↔ `workflow.go` (thin
   callback) ↔ `domain/` (pure logic).
4. **Describe yourself at registration** — meaningful identifiers, flags, usage
   strings, content types. They become CLI help, IDE tooltips, and MCP
   descriptions.
5. **Route by content type**, wrap errors with `%w`, use error-catalog types for
   user-facing problems, clone config before cross-workflow invocation.

---

## Working agreements

- **Plan first.** For non-trivial changes, save an implementation plan under
  `${issueID}_implementation_plan/` (issueID is the `XXX-XXXX` token in the
  branch name) and get it reviewed by the user before editing production code.
  Do not commit the plan to the final PR.
- **Minimal, on-target changes.** Don't refactor or optimize beyond the goal.
  Match existing patterns and conventions.
- **Tests always.** Write/update unit tests AND integration tests and iterate until they pass. Use
  `t.Setenv` (never `os.Setenv`). Use existing `gomock`-generated mocks; don't
  hand-roll new ones. Don't fix test data to make tests pass.
- **Run the tooling before committing:** `make format`, `make lint`,
  `make test`, `make generate`. Then verify `git diff --name-only` is clean
  (stage anything the tools changed).
- **Security:** run `snyk code test <absolute-project-path>` after code edits
  and `snyk test <absolute-project-path>` after `go.mod` changes. Fix fixable
  findings (not in test data).
- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/)
  (`type: summary`); subject under 72 chars + descriptive body; append
  `[XXX-XXXX]` from the branch name. Each commit must stand on its own without
  breaking the release pipeline. Never force-push; always confirm with the user
  before pushing.

---

## Clean code values

We follow the [Clean Code Developer](https://clean-code-developer.de/en/the-straight/)
value system. Its grades are a cumulative ladder; below we list the code-design
**principles** of each grade with a concrete GAF example. These are the ones that
directly shape a stable, multi-consumer framework. Most are demonstrated in full
in the [Extension Architecture Guide](docs/extension-architecture-guide.md) —
follow the links for the worked examples.

### 🔴 Red — foundational design
- **DRY** — a fact lives in one place; e.g. define a config key or content type
  as a single exported constant, not a string literal repeated across callbacks.
- **KISS** — prefer the straightforward workflow over a clever one; a thin
  callback calling a plain domain function beats premature abstraction.
- **Favour Composition over Inheritance** — compose behavior via interfaces and
  functional options (`WithConfig`, `WithInput`) rather than type hierarchies.
- **IOSP (Integration/Operation Segregation)** — a function either *integrates*
  (composes calls) or *operates* (does logic), never both; this is the
  [thin-callback rule](docs/extension-architecture-guide.md#1-the-workflow-is-a-thin-integration-shell).

### 🟠 Orange — single-purpose, readable units
- **Single Responsibility (SRP)** — a workflow does one thing; split
  `ignore.create` / `ignore.edit` rather than overloading one callback.
- **Separation of Concerns** — keep registration (`init.go`), wiring
  (`workflow.go`), and logic (`domain/`) in distinct layers.
- **Single Level of Abstraction** — don't mix high-level orchestration and
  byte-fiddling in the same function.

### 🟡 Yellow — isolation & stable interfaces
- **Dependency Inversion (DIP)** — `domain/` depends on `context.Context`,
  `*http.Client`, and config values — never on `InvocationContext` (see
  [Testability](docs/extension-architecture-guide.md#4-testability) and the
  [Anti-Patterns](docs/extension-architecture-guide.md#anti-patterns)).
- **Interface Segregation (ISP)** — expose small, focused interfaces so consumers
  don't take a dependency on methods they don't use.
- **Information Hiding** — keep implementation in `internal/`; expose only what
  the public contract needs.
- **Least Astonishment** — a load-bearing stability rule: consumers must not be
  surprised by a changed signature, default, or behavior.

### 🟢 Green — extensibility
- **Open/Closed (OCP)** — the framework's north star: extend via new
  workflows/extensions and functional options, don't modify existing public
  behavior.
- **Tell, Don't Ask** — hand work to a type rather than pulling out its state and
  acting on it externally.
- **Law of Demeter** — avoid reaching through object graphs
  (`a.GetB().GetC().Do()`); keep interactions shallow.

### 🔵 Blue — architecture-level
- **YAGNI** — don't add speculative public API you'd then have to keep stable
  forever; add it when a consumer actually needs it.
- **Component Orientation** — the engine-plus-extensions (microkernel) model;
  build features as self-describing, independently-contractable components (see
  [The Microservice Analogy](docs/extension-architecture-guide.md#the-microservice-analogy)).
- **Implementation Reflects Design** — the package layout should physically
  mirror the intended architecture.

> Each grade also carries **practices** (version control, reviews, automated
> unit/integration tests, CI, `make lint`, gomock test doubles, conventional
> commits) — these live in [Working agreements](#working-agreements) and the
> [Task execution checklist](#task-execution-checklist) above rather than being
> repeated here.

---

## Setup

Requires **Go 1.26+**. Install dev tools:

```bash
make tools        # installs golangci-lint v2.10.1 into .bin/
```

---

## Task execution checklist

When you receive a task, follow this sequence:

1. **Orient** — identify affected packages; check if they are in `pkg/`
   (public) or `internal/` (private). If public, apply the stability checklist.
2. **Plan** — for non-trivial work, draft an implementation plan and confirm
   with the user.
3. **Write/update tests** — before or alongside the implementation.
4. **Implement** — keep the change minimal and on-target.
5. **Verify** — run `make format && make lint && make test && make generate`.
6. **Check for drift** — `git diff --name-only`; stage anything the tools
   changed.
7. **Commit** — conventional-commit format, descriptive body.

---

## Quick reference

```bash
make help        # list all targets
make tools       # install golangci-lint
make format      # gofmt
make lint        # golangci-lint
make test        # unit tests with race detector
make generate    # regenerate mocks and API clients
```

Local development against a consumer (e.g. the CLI) — add to the consumer's `go.mod`:

```
replace github.com/snyk/go-application-framework => ../../go-application-framework
```
