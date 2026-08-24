# CLI contributor billing — E2E (condensed)

Five in-scope paths: **monitor legacy**, **iac test --report**, **code test --report** (native + legacy), **aibom --upload**. Monitor native (Dragonfly) is out of scope.

**Pass:** mitmweb shows exactly one `POST .../contributing_devs?version=2024-10-15` with `billing-test@example.com` in `contributors[]`. AIBOM uses `contributors_entity_type: "revision"`.

## Stack

| Repo | Branch |
|------|--------|
| GAF | `feat/contributor-capture-wiring` |
| CLI (`~/cli/cliv2`) | `chore/CLI-1743_ac` |

`~/cli/cliv2/go.mod` must have (uncommented):

```go
replace github.com/snyk/go-application-framework => ../../go-application-framework
```

## Pre-flight + build

```bash
GAF=~/go-application-framework
bash "$GAF/internal/contributors/docs/scripts/cli-billing-lazy-open-preflight.sh"
# one path: ... --path monitor-legacy|iac|code-native|code-legacy|aibom
```

Builds `~/bin/snyk-billing` if checks pass.

## mitmweb session

**Tab 1** (leave running):

```bash
mitmweb --listen-port 8080 --ssl-insecure
```

**Tab 2** before each command:

```bash
source ~/go-application-framework/internal/contributors/docs/scripts/cli-billing-mitm-env.sh
# non-monitor paths:
unset SNYK_FORCE_LEGACY_CLI
```

Sanity: `curl --cacert "$NODE_EXTRA_CA_CERTS" -x "$HTTPS_PROXY" 'https://example.com' -I` → **200** (not 502).

Filter mitmweb for `contributing_devs` → **Request → JSON**.

## `snyk.json` (always)

`~/.config/configstore/snyk.json`:

```json
{
  "org": "<your-org-uuid>",
  "contributor_billing_capture_enabled": true
}
```

Per-path routing keys (edit before that path; flip when switching):

| Path | Keys to set |
|------|-------------|
| Monitor legacy | `"internal_snyk_cli_rollout_dfly_os_cli": false` + `export SNYK_FORCE_LEGACY_CLI=true` (mitm-env sets this) |
| IaC | No local key — org needs `iacCliShareResults` ON |
| Code legacy | `"internal_snyk_code_ignores_enabled": false`, `"internal_snyk_code_native_implementation": false` |
| Code native | `"internal_snyk_code_ignores_enabled": true` (or `native_implementation: true`) |
| AIBOM | Org needs AI-BOM entitlement |

## One-time fixtures

Use `billing-test@example.com` / `Billing Test` on every fixture.

**Monitor** — `~/cli/cliv2/test/fixtures/npm-test-proj-no-vulns`:

```bash
cd ~/cli/cliv2/test/fixtures/npm-test-proj-no-vulns
test -d .git || git init
git config user.email "billing-test@example.com"
git config user.name "Billing Test"
git add .
git commit -m "fixture for contributor billing test" || true
```

**IaC** — `~/cli/test/fixtures/iac/file-output`:

```bash
cd ~/cli/test/fixtures/iac/file-output
test -d .git || git init
git config user.email "billing-test@example.com"
git config user.name "Billing Test"
git add .
git commit -m "fixture for contributor billing iac test" || true
```

**Code** (native + legacy) — `~/cli-fixtures/snyk-goof-billing`:

```bash
FIXTURE=~/cli-fixtures/snyk-goof-billing
mkdir -p "$(dirname "$FIXTURE")"
[[ -d "$FIXTURE/.git" ]] || git clone --depth 1 https://github.com/snyk/snyk-goof.git "$FIXTURE"
cd "$FIXTURE"
git config user.email "billing-test@example.com"
git config user.name "Billing Test"
echo "// billing e2e" >> app.js
git add app.js && git commit -m "fixture for contributor billing code test" || true
```

**AIBOM** — `~/cli/test/fixtures/ai-bom/python-chatbot`:

```bash
cd ~/cli/test/fixtures/ai-bom/python-chatbot
test -d .git || git init
git config user.email "billing-test@example.com"
git config user.name "Billing Test"
git add .
git commit -m "fixture for contributor billing aibom upload" || true
```

## Run commands

Set `snyk.json` for the path, then from Tab 2 (proxy env sourced):

### 1. Monitor legacy

```bash
export SNYK_FORCE_LEGACY_CLI=true
cd ~/cli/cliv2/test/fixtures/npm-test-proj-no-vulns
"$SNYK_BILLING_BIN" monitor
echo "exit: $?"
```

### 2. IaC

```bash
unset SNYK_FORCE_LEGACY_CLI
cd ~/cli/test/fixtures/iac/file-output
"$SNYK_BILLING_BIN" iac test --report .
echo "exit: $?"
```

### 3. Code legacy

Both Code native keys `false` in `snyk.json`.

```bash
unset SNYK_FORCE_LEGACY_CLI
cd ~/cli-fixtures/snyk-goof-billing
"$SNYK_BILLING_BIN" code test --report --project-name=billing-test-goof-legacy .
echo "exit: $?"
```

### 4. Code native

At least one Code native key `true` in `snyk.json`.

```bash
unset SNYK_FORCE_LEGACY_CLI
cd ~/cli-fixtures/snyk-goof-billing
"$SNYK_BILLING_BIN" code test --report --project-name=billing-test-goof .
echo "exit: $?"
```

### 5. AIBOM

```bash
unset SNYK_FORCE_LEGACY_CLI
cd ~/cli/test/fixtures/ai-bom/python-chatbot
"$SNYK_BILLING_BIN" aibom . --experimental --upload --repo "python-chatbot"
echo "exit: $?"
```

Suggested order (minimal FF churn): code legacy → monitor legacy → iac → code native → aibom.
