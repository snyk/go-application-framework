# AGENTS.md — `pkg/local_workflows`

The [root AGENTS.md](../../AGENTS.md) rules apply here too. This file covers what is specific to this layer.

## What this layer is

`pkg/local_workflows/` sits on top of the generic packages in `pkg/` and adds Snyk-specific primitives: the built-in
workflows and the helpers around them. The name is a bit unlucky, as not everything here is a workflow. It is where
Snyk-specific behavior (such as env var prefixes or product terms) is allowed. Generic `pkg/*` packages must not
hardcode it.

## Conventions

- Helpers live in `*_utils` packages. Reuse one if it fits, otherwise follow the pattern.
- If a helper needs Snyk-specific behavior (e.g. the `SNYK_` env var prefix), keep the generic mechanism in `pkg/` and the Snyk-specific part here.
- Define Snyk-specific constants once, in the package that uses them.
- Use the [error catalog](https://github.com/snyk/error-catalog) for errors that reach users.
- Workflows read values through `Configuration`. Helpers that must work on a raw environment (such as child process
  setup) are the exception: keep them small and pure.
