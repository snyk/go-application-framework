# Shared pre-flight library for contributor billing E2E.
# Sourced by cli-billing-lazy-open-preflight.sh — do not run directly.

set -uo pipefail

GAF="${GAF:-$HOME/go-application-framework}"
CLI="${CLI:-$HOME/cli/cliv2}"
CLI_ROOT="${CLI_ROOT:-$HOME/cli}"
BIN="${BIN:-$HOME/bin/snyk-billing}"
EXPECT_GAF_BRANCH="${EXPECT_GAF_BRANCH:-feat/contributor-capture-wiring}"
EXPECT_CLI_BRANCH="${EXPECT_CLI_BRANCH:-chore/CLI-1743_ac}"
GUIDE="${GUIDE:-${GAF}/internal/contributors/docs/cli-billing-e2e.md}"

failures=0

fail() {
  echo "FAIL: $*" >&2
  failures=$((failures + 1))
}

pass() {
  echo "OK: $*"
}

warn() {
  echo "WARN: $*" >&2
}

grep_file() {
  local pattern=$1 file=$2
  if command -v rg >/dev/null 2>&1; then
    rg -q "$pattern" "$file"
  else
    grep -qE "$pattern" "$file"
  fi
}

grep_file_absent() {
  local pattern=$1 file=$2
  if command -v rg >/dev/null 2>&1; then
    ! rg -q "$pattern" "$file"
  else
    ! grep -qE "$pattern" "$file"
  fi
}

PREFLIGHT_PATH_IDS=(
  monitor-legacy
  iac
  code-native
  code-legacy
  aibom
)

preflight_path_command() {
  case "$1" in
    monitor-legacy) echo 'monitor (legacy)' ;;
    iac) echo 'iac test --report' ;;
    code-native) echo 'code test --report (native)' ;;
    code-legacy) echo 'code test --report (legacy)' ;;
    aibom) echo 'aibom --upload' ;;
    *) return 1 ;;
  esac
}

preflight_path_fixture() {
  case "$1" in
    monitor-legacy) echo "${FIXTURE_MONITOR:-$CLI/test/fixtures/npm-test-proj-no-vulns}" ;;
    iac) echo "${FIXTURE_IAC:-$CLI_ROOT/test/fixtures/iac/file-output}" ;;
    code-native | code-legacy) echo "${FIXTURE_CODE:-$HOME/cli-fixtures/snyk-goof-billing}" ;;
    aibom) echo "${FIXTURE_AIBOM:-$CLI_ROOT/test/fixtures/ai-bom/python-chatbot}" ;;
    *) return 1 ;;
  esac
}

preflight_path_fixture_hint() {
  case "$1" in
    monitor-legacy) echo "Run monitor fixture block in $GUIDE" ;;
    iac) echo "Run IaC fixture block in $GUIDE" ;;
    code-native | code-legacy) echo "Run Code fixture block in $GUIDE" ;;
    aibom) echo "Run AIBOM fixture block in $GUIDE" ;;
  esac
}

preflight_path_middleware_tests() {
  case "$1" in
    monitor-legacy) echo 'TestContributorCaptureMiddleware_capturesMonitorProjectID' ;;
    iac) echo 'TestContributorCaptureMiddleware_capturesIaCShareProjectIDs' ;;
    code-native)
      echo 'TestContributorCaptureMiddleware_capturesTestAPIComponentsFlow|TestContributorCaptureMiddleware_capturesTestAPIComponentsFlowWithLegacyPublishReport'
      ;;
    code-legacy)
      echo 'TestContributorCaptureMiddleware_capturesDeeproxyReportProjectID|TestContributorCaptureMiddleware_capturesGzipEncodedDeeproxyReport'
      ;;
    aibom) echo 'TestContributorCaptureMiddleware_capturesAIBomUploadRevisionIDFromRequestBody' ;;
  esac
}

preflight_all_middleware_tests() {
  preflight_path_middleware_tests monitor-legacy
  echo '|'
  preflight_path_middleware_tests iac
  echo '|'
  preflight_path_middleware_tests code-native
  echo '|'
  preflight_path_middleware_tests code-legacy
  echo '|'
  preflight_path_middleware_tests aibom
}

preflight_path_warnings() {
  case "$1" in
    monitor-legacy)
      warn "monitor legacy: set internal_snyk_cli_rollout_dfly_os_cli false in snyk.json — see $GUIDE"
      warn "monitor legacy: export SNYK_FORCE_LEGACY_CLI=true if org has Dragonfly ON"
      ;;
    iac)
      warn "iac: iacCliShareResults has no snyk.json key — enable on org — see $GUIDE"
      ;;
    code-native)
      warn "code native: set internal_snyk_code_* in snyk.json — see $GUIDE"
      ;;
    code-legacy)
      warn "code legacy: set both internal_snyk_code_* keys to false in snyk.json — see $GUIDE"
      ;;
    aibom)
      warn "aibom: requires --experimental; org needs AI-BOM entitlement — see $GUIDE"
      ;;
  esac
}

preflight_shared() {
  echo "── 1. Repo paths ──"
  for dir in "$GAF" "$CLI"; do
    if [[ -d "$dir" ]]; then
      pass "$dir"
    else
      fail "missing directory: $dir (set GAF/CLI if paths differ)"
    fi
  done

  echo "── 2. Branches ──"
  if [[ -d "$GAF/.git" ]]; then
    gaf_branch=$(git -C "$GAF" branch --show-current)
    if [[ "$gaf_branch" == "$EXPECT_GAF_BRANCH" ]]; then
      pass "GAF branch $gaf_branch"
    else
      warn "GAF branch is '$gaf_branch' (expected '$EXPECT_GAF_BRANCH')"
    fi
  fi
  if [[ -d "$CLI/.git" ]]; then
    cli_branch=$(git -C "$CLI" branch --show-current)
    if [[ "$cli_branch" == "$EXPECT_CLI_BRANCH" ]]; then
      pass "CLI branch $cli_branch"
    else
      warn "CLI branch is '$cli_branch' (expected '$EXPECT_CLI_BRANCH')"
    fi
  fi

  echo "── 3. GAF billing wiring ──"
  capture_mw="$GAF/pkg/networking/middleware/contributor_capture/contributor_capture.go"
  wiring_go="$GAF/internal/contributors/wiring/wiring.go"
  sink_go="$GAF/internal/contributors/sink.go"
  emitter_go="$GAF/internal/contributors/emitter.go"
  app_go="$GAF/pkg/app/app.go"

  if [[ -f "$capture_mw" ]]; then
    grep_file 'completeRequestCapture' "$capture_mw" \
      && pass 'middleware completeRequestCapture' \
      || fail 'missing completeRequestCapture in contributor_capture middleware'
    grep_file 'RecordEntity' "$capture_mw" \
      && pass 'middleware records captured entity in sink' \
      || fail 'missing sink RecordEntity call in contributor_capture middleware'
  else
    fail "missing $capture_mw"
  fi

  if [[ -f "$sink_go" ]]; then
    grep_file 'func Enable' "$sink_go" \
      && pass 'contributors.Enable sink gate' \
      || fail 'missing contributors.Enable in sink.go'
    grep_file 'func GetSink' "$sink_go" \
      && pass 'contributors.GetSink' \
      || fail 'missing GetSink in sink.go'
  else
    fail "missing $sink_go"
  fi

  if [[ -f "$wiring_go" ]]; then
    grep_file 'func Init' "$wiring_go" \
      && pass 'contributor wiring Init' \
      || fail 'missing wiring.Init'
    grep_file 'waitForEmit' "$wiring_go" \
      && pass 'waitForEmit blocks until ingest POST completes' \
      || fail 'missing waitForEmit in wiring.go'
    grep_file 'WORKFLOWID_REPORT_ANALYTICS' "$wiring_go" \
      && pass 'hook skips analytics.report' \
      || fail 'hook should skip WORKFLOWID_REPORT_ANALYTICS'
  else
    fail "missing $wiring_go"
  fi

  if [[ -f "$emitter_go" ]]; then
    grep_file 'func \(e \*Emitter\) Emit' "$emitter_go" \
      && pass 'contributors.Emit POSTs ingest payload' \
      || fail 'missing Emitter.Emit in emitter.go'
  else
    fail "missing $emitter_go"
  fi

  if [[ -f "$app_go" ]]; then
    grep_file 'contributorwiring.Init' "$app_go" \
      && pass 'app.go contributorwiring.Init via AddExtensionInitializer' \
      || fail 'missing contributorwiring.Init in pkg/app/app.go'
    grep_file 'ConfigurationKeyCaptureEnabled' "$app_go" \
      && pass 'capture flag mapped in app init' \
      || fail 'missing contributors.ConfigurationKeyCaptureEnabled mapping in app.go'
  else
    fail "missing $app_go"
  fi

  echo "── 4. CLI billing surface (zero cliv2 wiring) ──"
  main_go="$CLI/pkg/core/main.go"
  if [[ -f "$main_go" ]]; then
    grep_file 'CreateAppEngineWithOptions' "$main_go" \
      && pass 'CreateAppEngineWithOptions in main.go' \
      || fail 'missing CreateAppEngineWithOptions in main.go'
    grep_file_absent 'FinishCommand' "$main_go" \
      && pass 'no FinishCommand in main.go' \
      || fail 'remove clibilling.FinishCommand from main.go (billing is GAF-only)'
    grep_file_absent 'EnableIfConfigured' "$main_go" \
      && pass 'no EnableIfConfigured in main.go' \
      || fail 'remove clibilling.EnableIfConfigured from main.go (billing is GAF-only)'
    grep_file_absent 'pkg/clibilling' "$main_go" \
      && pass 'no clibilling import in main.go' \
      || fail 'remove clibilling import from main.go'
    if [[ -f "$CLI/pkg/basic_workflows/mainworkflow.go" ]] \
      && grep_file 'MAIN_WORKLFOW_ID' "$CLI/pkg/basic_workflows/mainworkflow.go"; then
      pass 'main workflow present (chore/CLI-1743_ac)'
    else
      warn 'main workflow not found — expected on chore/CLI-1743_ac'
    fi
  else
    fail "missing $main_go"
  fi

  echo "── 5. go.mod replace ──"
  if [[ -f "$CLI/go.mod" ]] && grep -q 'replace github.com/snyk/go-application-framework' "$CLI/go.mod"; then
    pass 'go.mod replace points at local GAF'
    grep 'replace github.com/snyk/go-application-framework' "$CLI/go.mod" || true
  else
    fail 'add replace github.com/snyk/go-application-framework => ../../go-application-framework to cliv2/go.mod'
  fi

  echo "── 6. Snyk auth + org ──"
  if command -v snyk >/dev/null 2>&1; then
    if snyk config get api >/dev/null 2>&1; then
      pass 'snyk api configured'
    else
      warn 'snyk config get api failed — set: snyk config set api=...'
    fi
    org=$(snyk config get org 2>/dev/null | head -1 | tr -d '[:space:]')
    if [[ -n "$org" && "$org" != "null" && "$org" != ERROR* ]]; then
      pass "org=$org"
    else
      warn 'org empty — E2E will not POST; run: snyk config set org=<uuid>'
    fi
  else
    warn 'snyk not on PATH — skipping auth/org checks (use built ~/bin/snyk-billing for E2E)'
  fi

  echo "── 7. Capture flag ──"
  python3 -c "
import json, os
p = os.path.expanduser('~/.config/configstore/snyk.json')
d = json.load(open(p)) if os.path.exists(p) else {}
v = d.get('contributor_billing_capture_enabled', '<not set>')
print('contributor_billing_capture_enabled =', v)
if v is not True:
    print('  → add \"contributor_billing_capture_enabled\": true to snyk.json')
"

  echo "── 8. Build billing CLI ──"
  if [[ -d "$CLI" ]]; then
    if (cd "$CLI" && go build -mod=mod -tags application -o "$BIN" ./cmd/cliv2); then
      pass "built $BIN"
      if [[ -x "$BIN" ]]; then
        pass "$BIN is executable"
      fi
    else
      fail "go build failed in $CLI (check go.mod replace and GAF compile errors)"
    fi
  else
    fail "cannot build — CLI path missing"
  fi
}

preflight_fixture() {
  local path_id=$1
  local command fixture hint

  command=$(preflight_path_command "$path_id") || {
    fail "unknown path id: $path_id"
    return
  }
  fixture=$(preflight_path_fixture "$path_id") || {
    fail "unknown path id: $path_id"
    return
  }
  hint=$(preflight_path_fixture_hint "$path_id")

  echo "  [$command] $fixture"
  if [[ -d "$fixture" ]]; then
    pass "fixture directory exists"
  else
    fail "missing fixture directory: $fixture"
    [[ -n "$hint" ]] && echo "     $hint" >&2
    return
  fi

  if [[ -d "$fixture/.git" ]]; then
    pass "fixture has .git"
    git -C "$fixture" log -1 --format='email=%ae date=%ad' || fail 'fixture git log failed'
    if git -C "$fixture" log -1 --format='%ae' 2>/dev/null | grep -q 'billing-test@example.com'; then
      pass 'fixture latest commit uses billing-test@example.com'
    else
      warn "fixture latest commit is not billing-test@example.com — ingest may differ from guide"
    fi
  else
    fail "no .git in $fixture"
    [[ -n "$hint" ]] && echo "     $hint" >&2
  fi
}

preflight_fixtures() {
  local path_id
  echo "── 9. Git fixtures ──"
  for path_id in "$@"; do
    preflight_fixture "$path_id"
  done
}

preflight_middleware_tests() {
  local run_filter=$1
  local label=${2:-middleware capture tests}

  echo "── 10. GAF unit sanity ($label) ──"
  if [[ ! -d "$GAF" ]]; then
    fail "cannot test GAF — path missing"
    return
  fi

  if (cd "$GAF" && go test -count=1 ./internal/contributors/... \
    -run 'TestInit_respectsCaptureFlag|TestWaitForEmit|TestContributorSink|TestGetSink|TestEmit'); then
    pass 'contributors sink / wiring tests'
  else
    fail 'contributors package tests failed'
  fi

  if (cd "$GAF" && go test -count=1 ./pkg/networking/middleware/contributor_capture/... -run "$run_filter"); then
    pass "$label"
  else
    fail 'middleware tests failed'
  fi
}

preflight_finish() {
  local scope=$1
  echo ""
  if [[ "$failures" -eq 0 ]]; then
    echo "✅ Pre-flight passed ($scope) — proceed to mitmweb E2E (see $GUIDE)"
    exit 0
  fi
  echo "❌ Pre-flight finished with $failures failure(s) — fix the FAIL lines above"
  exit 1
}
