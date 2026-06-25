# UFM presenter test fixtures

Snapshot inputs and expected outputs for `Test_UfmPresenter_*` in [`presenter_ufm_test.go`](../../presenter_ufm_test.go).

Workflow overview: [CONTRIBUTING.md](../../../../CONTRIBUTING.md#ufm-test-fixtures).

## Fixture catalog

| Basename | Type | SARIF | Human | HTML | Metadata (`*.testresult.json`) | Test config | Regeneration |
|----------|------|:-----:|:-----:|:----:|--------------------------------|-------------|--------------|
| `testresult_cli` | live | ✓ (`original_cli.sarif`) | ✓ (`cli.human.readable`) | ✓ | `project-name: snyk`, `display-target-file: package-lock.json` | SARIF: `ignoreSuppressions=true`; human: defaults | `SCAN_CMD="test ."`, `PROJECT=<snyk/cli checkout>`, `ORG=my-org` |
| `webgoat` | live | ✓ (`webgoat.sarif.json`) | — | — | `project-name: org.owasp.webgoat:webgoat`, `display-target-file: pom.xml` | SARIF: `ignoreSuppressions=true` | `SCAN_CMD="test ."`, `PROJECT=~/workspace/WebGoat`, `ORG=my-org` |
| `webgoat.ignore` | live | ✓ (`webgoat.ignore.sarif.json`) | ✓ (`webgoat.ignore.human.readable`) | — | same project as `webgoat`; policy includes ignores | SARIF: `ignoreSuppressions=false`; human: `includeIgnores=true`, `severityThreshold=medium` | same as `webgoat` (`PROJECT=~/workspace/WebGoat`); scan org/policy must include configured ignores |
| `multi_project` | live | ✓ (`multi_project.sarif.json`) | ✓ (`multi_project.human.readable`) | — | 6 sub-projects (`python`, `golangproject`, `package.json`, …); legacy `tpwe` dotnet project removed from committed fixtures | SARIF: `ignoreSuppressions=true`; human: defaults | **not live-regenerated in CLI-1510** — see below |
| `secrets` | synthetic | ✓ | ✓ | — | placeholder `testId`, no `metadata.project-name` | SARIF: `ignoreSuppressions=true`; human: `includeIgnores=true` | hand-maintained; do not regenerate via live scan |
| `secrets.0findings` | synthetic | ✓ | — | — | placeholder `testId`, zero findings | SARIF: `ignoreSuppressions=true` | hand-maintained |
| `secrets.duplicated-sarif-rules` | synthetic | ✓ | ✓ | — | placeholder `testId`; multiple findings share SARIF rule IDs | SARIF: `ignoreSuppressions=true`; human: `includeIgnores=true` | hand-maintained |
| `secrets.with-report` | synthetic | ✓ | ✓ | — | placeholder `testId`; includes report URL in output | SARIF: `ignoreSuppressions=true`; human: `includeIgnores=true` | hand-maintained synthetic — do not regenerate; models `--report` URL (see `REPORT=1` in `generate-fixture.sh` for live `secrets` dumps only) |

**Planned (CLI-1510 Phase 2):** `python_pins` — synthetic fixture for `Pin … to …` human-readable remediation (not yet added).

### Multi-project sub-projects

From `multi_project.testresult.json` (live dump of `--all-projects`; `tpwe` dotnet project excluded):

| `project-name` | `display-target-file` | `target-directory` |
|----------------|----------------------|--------------------|
| `package.json` | `ghost/package.json` | `multi-project` |
| `golangproject` | `golang/go.mod` | `multi-project` |
| `demo:maven-demo` | `maven/pom.xml` | `multi-project` |
| `not-python` | `not-python/requirements.txt` | `multi-project` |
| `python` | `python/requirements.txt` | `multi-project` |
| `tsc` | `tsc/package.json` | `multi-project` |

The original dump also included `tpwe` (`dotnet/obj/project.assets.json`) from a personal .NET project. CLI-1510 removed that sub-project from the committed `*.testresult.json` and `*.sarif.json` inputs; there is no maintained source checkout for a full live regen.

### Synthetic vs live

- **Live:** produced via `make generate-fixture` from a real `snyk test` (or `secrets test`) scan, then redacted with `ufm-fixture-tool`.
- **Synthetic:** hand-edited `*.testresult.json` for deterministic edge cases (secrets variants, zero findings, duplicated SARIF rules). Placeholder `testId` `11111111-2222-3333-4444-555555555555` is intentional.

## Regenerating fixtures

### Prerequisites

- `snyk auth` and org access
- CLI build with the GAF in-memory threshold fix (CLI-1509)
- For Maven/Java projects (WebGoat): `JAVA_HOME` must point at a JDK; warm the wrapper first (`./mvnw --version`) or `snyk test` can hang on `maven-wrapper --version`
- For OSS `snyk test`, `make generate-fixture` sets `INTERNAL_SNYK_CLI_USE_UNIFIED_TEST_API_FOR_OS_CLI_TEST=true` so the unified Test API path emits `workflow.TestResult` dumps (org FF not required)

Set once per session (adjust paths):

```bash
export SNYK_BIN=/path/to/snyk          # e.g. snyk/cli binary-releases build
export ORG=my-org-slug                 # e.g. platform_hammerhead_testing
export JAVA_HOME=/path/to/jdk          # WebGoat only; optional otherwise
```

### Live fixture recipes

Run from the **go-application-framework** repo root. Outputs land in `dumps/<NAME>.testresult.json`.

| `NAME=` | `PROJECT` (example) | `SCAN_CMD` | Copy dump to |
|---------|---------------------|------------|--------------|
| `testresult_cli` | `<snyk/cli checkout>` | `test .` | `testresult_cli.json` |
| `webgoat` | `<OWASP WebGoat checkout>` | `test .` | `webgoat.testresult.json` |
| `webgoat_ignore` | *(same scan as `webgoat`)* | — | `webgoat.ignore.testresult.json` |

`webgoat.ignore` uses the **same** redacted dump as `webgoat` (copy the file; do not re-scan). Expected SARIF/human output differs via test config (`ignoreSuppressions`, `includeIgnores`), not a second scan.

**`testresult_cli`**

```bash
make generate-fixture \
  PROJECT=/path/to/snyk/cli \
  ORG="$ORG" \
  NAME=testresult_cli \
  SNYK_BIN="$SNYK_BIN" \
  SCAN_CMD="test ."
cp dumps/testresult_cli.testresult.json internal/presenters/testdata/ufm/testresult_cli.json
```

Verify: `metadata.project-name` is `snyk`, `display-target-file` is `package-lock.json`.

**`webgoat` (+ `webgoat.ignore` input)**

```bash
make generate-fixture \
  PROJECT=/path/to/WebGoat \
  ORG="$ORG" \
  NAME=webgoat \
  SNYK_BIN="$SNYK_BIN" \
  SCAN_CMD="test ."
cp dumps/webgoat.testresult.json internal/presenters/testdata/ufm/webgoat.testresult.json
cp dumps/webgoat.testresult.json internal/presenters/testdata/ufm/webgoat.ignore.testresult.json
```

Verify: `metadata.project-name` is `org.owasp.webgoat:webgoat` (not `snyk`). Finding count drifts with the vuln DB — check project name, not count.

**Scoped expected-output regen** (preferred over `make regenerate-expected`, which rewrites every SARIF snapshot):

```bash
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_Sarif/cli$' -count=1
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_HumanReadable/cli$' -count=1
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_HTML/cli$' -count=1
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_Sarif/webgoat$' -count=1
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_Sarif/webgoat_with_suppression$' -count=1
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_HumanReadable/webgoat$' -count=1
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_Sarif/multiproject$' -count=1
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_HumanReadable/multi_project$' -count=1
go test ./internal/presenters/... -run 'Test_UfmPresenter' -count=1
```

Quick verify after dump:

```bash
python3 -c "import json; d=json.load(open('dumps/webgoat.testresult.json'))[0]; print(d['metadata']['project-name'])"
```

### Generic `make generate-fixture`

```bash
make generate-fixture \
  PROJECT=/path/to/scanned-repo \
  ORG="$ORG" \
  NAME=fixture_basename \
  SNYK_BIN="$SNYK_BIN" \
  SCAN_CMD="test ."          # or "secrets test .", etc.
# optional: REPORT=1 for commands that support --report
```

Copy `dumps/<name>.testresult.json` into this directory. Add or update test rows in `presenter_ufm_test.go` only when introducing a **new** fixture.

### Expected snapshots only

When presenter templates change but inputs are unchanged, regen only the affected test cases with scoped `UFM_REGEN` (see above). Full regen:

```bash
make regenerate-expected
```

Equivalent to `UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter' -count=1`. Review diffs before committing.
