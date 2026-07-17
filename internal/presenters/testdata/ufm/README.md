# UFM presenter test fixtures

Snapshot inputs and expected outputs for `Test_UfmPresenter_*` in [`presenter_ufm_test.go`](../../presenter_ufm_test.go).

Workflow overview: [CONTRIBUTING.md](../../../../CONTRIBUTING.md#ufm-test-fixtures).

## Fixture catalog

| Basename | Type | SARIF | Human | HTML | Metadata (`*.testresult.json`) | Test config | Regeneration |
|----------|------|:-----:|:-----:|:----:|--------------------------------|-------------|--------------|
| `testresult_cli` | live | ✓ (`original_cli.sarif`) | ✓ (`cli.human.readable`) | ✓ | `project-name: snyk`, `display-target-file: package-lock.json` | SARIF: `ignoreSuppressions=true`; human: defaults | see [commit pins](#commit-pins) |
| `webgoat` | live | ✓ (`webgoat.sarif.json`) | — | — | `project-name: org.owasp.webgoat:webgoat`, `display-target-file: pom.xml` | SARIF: `ignoreSuppressions=true` | see [commit pins](#commit-pins) |
| `webgoat.ignore` | live | ✓ (`webgoat.ignore.sarif.json`) | ✓ (`webgoat.ignore.human.readable`) | — | same project as `webgoat`; policy includes ignores | SARIF: `ignoreSuppressions=false`; human: `includeIgnores=true`, `severityThreshold=medium` | same input as `webgoat` (copy dump; do not re-scan) |
| `snyk_goof` | live | ✓ (`snyk_goof.sarif.json`) | — | — | `project-name: goof`, `display-target-file: package-lock.json` | SARIF: `ignoreSuppressions=true` | see [commit pins](#commit-pins) |
| `python_pip_app_jarvis2` | live | ✓ (`python_pip_app_jarvis2.sarif.json`) | ✓ (`python_pip_app_jarvis2.human.readable`) | — | `project-name: python-pip-app-jarvis2`, `display-target-file: requirements.txt` | SARIF: `ignoreSuppressions=true`; human: defaults | see [commit pins](#commit-pins); Python venv required |
| `multi_project` | live | ✓ (`multi_project.sarif.json`) | ✓ (`multi_project.human.readable`) | — | 4 sub-projects (cli, webgoat, snyk-goof, jarvis2) | SARIF: `ignoreSuppressions=true`; human: defaults | see [multi-project tree](#multi-project-tree) |
| `secrets` | synthetic | ✓ | ✓ | — | placeholder `testId`, no `metadata.project-name` | SARIF: `ignoreSuppressions=true`; human: `includeIgnores=true` | hand-maintained; do not regenerate via live scan |
| `secrets.0findings` | synthetic | ✓ | — | — | placeholder `testId`, zero findings | SARIF: `ignoreSuppressions=true` | hand-maintained |
| `secrets.duplicated-sarif-rules` | synthetic | ✓ | ✓ | — | placeholder `testId`; multiple findings share SARIF rule IDs | SARIF: `ignoreSuppressions=true`; human: `includeIgnores=true` | hand-maintained |
| `secrets.with-report` | synthetic | ✓ | ✓ | — | placeholder `testId`; includes report URL in output | SARIF: `ignoreSuppressions=true`; human: `includeIgnores=true` | hand-maintained synthetic — do not regenerate; models `--report` URL (see `REPORT=1` in `generate-fixture.sh` for live `secrets` dumps only) |
| `reachability` | synthetic | — | ✓ (`reachability.human.readable`) | — | placeholder `testId`; SCA findings with `ReachabilityEvidence` | human: defaults | hand-maintained — unified OSS `snyk test` dumps no longer emit reachability; preserves `ufm.human.tmpl` reachability branch coverage |

### Commit pins

Live fixtures are generated from these repositories at pinned SHAs (last regenerated 2026-06-26):

| Repository | Pin (commit SHA) |
|------------|------------------|
| [snyk/cli](https://github.com/snyk/cli) | `fa3dbff60b64e54306c854b043039c67be00596f` |
| [WebGoat/WebGoat](https://github.com/WebGoat/WebGoat) | `acbe4efa5c434d5a53f6a60f3cfe3dc9e880ec6d` |
| [snyk-fixtures/snyk-goof](https://github.com/snyk-fixtures/snyk-goof) | `9d39c56df741e9e723061d925d7425869cfa3455` |
| [snyk-fixtures/python-pip-app-jarvis2](https://github.com/snyk-fixtures/python-pip-app-jarvis2) | `8037e6f18165b727ea8bd4bec7a2cf18b725944b` |

### Multi-project sub-projects

From `multi_project.testresult.json` (live dump of `--all-projects` over the [multi-project tree](#multi-project-tree)):

| `project-name` | `display-target-file` | `target-directory` |
|----------------|----------------------|--------------------|
| `snyk` | `package.json` | `multi-project` |
| `org.owasp.webgoat:webgoat` | `webgoat/pom.xml` | `multi-project` |
| `goof` | `snyk-goof/package-lock.json` | `multi-project` |
| `python-pip-app-jarvis2` | `python-pip-app-jarvis2/requirements.txt` | `multi-project` |

### Multi-project tree

Layout used for `multi_project` regeneration (not committed; build locally before scanning):

```text
multi-project/
  package.json          # copied from snyk/cli root (pinned SHA)
  package-lock.json     # copied from snyk/cli root (pinned SHA)
  webgoat/              # symlink → WebGoat checkout at pinned SHA
  snyk-goof/            # symlink → snyk-fixtures/snyk-goof at pinned SHA
  python-pip-app-jarvis2/  # symlink → python-pip-app-jarvis2 at pinned SHA (+ venv for scan)
```

Do **not** symlink the full `snyk/cli` monorepo into the tree — `--all-projects` would pick up every nested manifest in the CLI repo.

### Synthetic vs live

- **Live:** produced via `make generate-fixture` from a real `snyk test` (or `secrets test`) scan, then redacted with `ufm-fixture-tool`.
- **Synthetic:** hand-edited `*.testresult.json` for deterministic edge cases (secrets variants, zero findings, duplicated SARIF rules, reachability). Placeholder `testId` `11111111-2222-3333-4444-555555555555` is intentional. Live OSS regen via unified Test API no longer includes reachability evidence — use `reachability.testresult.json` for golden coverage of that presenter branch.

## Regenerating fixtures

### Prerequisites

- `snyk auth` and org access
- CLI build with the GAF in-memory threshold fix (CLI-1509)
- For Maven/Java projects (WebGoat): `JAVA_HOME` must point at a JDK; warm the wrapper first (`./mvnw --version`) or `snyk test` can hang on `maven-wrapper --version`
- For `python-pip-app-jarvis2`: Python 3.10 venv with `requirements.txt` packages installed (legacy pins may need fallback versions for packages that no longer build)
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
| `testresult_cli` | `<snyk/cli checkout @ pin>` | `test .` | `testresult_cli.json` |
| `webgoat` | `<WebGoat checkout @ pin>` | `test .` | `webgoat.testresult.json` |
| `webgoat_ignore` | *(same scan as `webgoat`)* | — | `webgoat.ignore.testresult.json` |
| `snyk_goof` | `<snyk-fixtures/snyk-goof @ pin>` | `test .` | `snyk_goof.testresult.json` |
| `python_pip_app_jarvis2` | `<python-pip-app-jarvis2 @ pin>` (venv active) | `test .` | `python_pip_app_jarvis2.testresult.json` |
| `multi_project` | `<multi-project tree>` | `test --all-projects` | `multi_project.testresult.json` |

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

**`multi_project`**

Build the [multi-project tree](#multi-project-tree) with all four repos at their pinned SHAs, then:

```bash
make generate-fixture \
  PROJECT=/path/to/multi-project \
  ORG="$ORG" \
  NAME=multi_project \
  SNYK_BIN="$SNYK_BIN" \
  SCAN_CMD="test --all-projects"
cp dumps/multi_project.testresult.json internal/presenters/testdata/ufm/multi_project.testresult.json
```

`generate-fixture.sh` merges all `workflow.TestResult.*` dumps from the scan and normalizes `metadata.target-directory` to `multi-project`.

**Scoped expected-output regen** (preferred over `make regenerate-expected`, which rewrites every SARIF snapshot):

```bash
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_Sarif/cli$' -count=1
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_HumanReadable/cli$' -count=1
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_HTML/cli$' -count=1
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_Sarif/webgoat$' -count=1
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_Sarif/webgoat_with_suppression$' -count=1
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_HumanReadable/webgoat$' -count=1
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_Sarif/snyk_goof$' -count=1
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_Sarif/python_pip_app_jarvis2$' -count=1
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_HumanReadable/python_pip_app_jarvis2$' -count=1
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_Sarif/multiproject$' -count=1
UFM_REGEN=1 go test ./internal/presenters/... -run 'Test_UfmPresenter_HumanReadable/multi_project$' -count=1
go test ./internal/presenters/... -run 'Test_UfmPresenter' -count=1
```

Quick verify after dump:

```bash
python3 -c "import json; d=json.load(open('dumps/webgoat.testresult.json'))[0]; print(d['metadata']['project-name'])"
python3 -c "import json; d=json.load(open('dumps/multi_project.testresult.json')); print(len(d), [x['metadata']['project-name'] for x in d])"
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
