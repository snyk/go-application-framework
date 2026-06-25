#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"

PROJECT="${PROJECT:-}"
ORG="${ORG:-}"
NAME="${NAME:-}"

SNYK_BIN="${SNYK_BIN:-snyk}"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/dumps}"
DUMP_DIR="${DUMP_DIR:-${OUT_DIR}/raw}"
DEFAULT_SCAN_CMD="${DEFAULT_SCAN_CMD:-secrets test .}"
SCAN_CMD="${SCAN_CMD:-${DEFAULT_SCAN_CMD}}"
REPORT="${REPORT:-0}"
REDACT="${REDACT:-1}"

read -r -a scan_args <<< "${SCAN_CMD}"

is_oss_test_scan() {
	[[ "${scan_args[0]:-}" == "test" ]]
}

if [[ -z "${PROJECT}" ]]; then
  echo "error: PROJECT is required" >&2
  exit 1
fi
if [[ -z "${ORG}" ]]; then
  echo "error: ORG is required" >&2
  exit 1
fi
if [[ -z "${NAME}" ]]; then
  echo "error: NAME is required" >&2
  exit 1
fi

# OSS `snyk test` routes to legacycli unless the unified Test API FF is on; only the
# unified path emits workflow.TestResult payloads we need. Config honors this env var
# before the org FF gateway (see CLI-1510). Not needed for `secrets test`.
if is_oss_test_scan; then
  export INTERNAL_SNYK_CLI_USE_UNIFIED_TEST_API_FOR_OS_CLI_TEST="${INTERNAL_SNYK_CLI_USE_UNIFIED_TEST_API_FOR_OS_CLI_TEST:-true}"
fi

mkdir -p "${DUMP_DIR}" "${OUT_DIR}"

if [[ "${REPORT}" == "1" ]]; then
  scan_args+=("--report")
fi
scan_args+=("--org=${ORG}")

echo "Generating fixture (${NAME})"
echo "  OUT_DIR=${OUT_DIR}"
echo "  DUMP_DIR=${DUMP_DIR} (SNYK_TMP_PATH)"
echo "  working directory for scan: ${PROJECT}"
echo ""
printf "Running (equivalent):\n"
printf "  cd %q\n" "${PROJECT}"
printf "  SNYK_TMP_PATH=%q INTERNAL_IN_MEMORY_THRESHOLD_BYTES=1 INTERNAL_CLEANUP_GLOBAL_TEMP_DIR_ENABLED=false" "${DUMP_DIR}"
if is_oss_test_scan; then
  printf " INTERNAL_SNYK_CLI_USE_UNIFIED_TEST_API_FOR_OS_CLI_TEST=%q" "${INTERNAL_SNYK_CLI_USE_UNIFIED_TEST_API_FOR_OS_CLI_TEST}"
fi
printf " %q" "${SNYK_BIN}"
for a in "${scan_args[@]}"; do
	printf " %q" "${a}"
done
echo
echo ""
set +e
(
  cd "${PROJECT}"
  SNYK_TMP_PATH="${DUMP_DIR}" \
  INTERNAL_IN_MEMORY_THRESHOLD_BYTES=1 \
  INTERNAL_CLEANUP_GLOBAL_TEMP_DIR_ENABLED=false \
    "${SNYK_BIN}" "${scan_args[@]}"
)
snyk_exit=$?
set -e

# Exit 1 is expected when findings are detected.
if [[ "${snyk_exit}" -ne 0 && "${snyk_exit}" -ne 1 ]]; then
  echo "error: snyk command failed with exit code ${snyk_exit}" >&2
  exit "${snyk_exit}"
fi

# GAF derives TEMP_DIR_PATH as <SNYK_TMP_PATH>/<cli-version>/tmp/pid<pid>, so
# the dump file lives in a nested subdirectory rather than directly under
# DUMP_DIR. Recurse and pick the newest match by mtime.
latest_dump=""
while IFS= read -r -d '' f; do
  if [[ -z "${latest_dump}" || "${f}" -nt "${latest_dump}" ]]; then
    latest_dump="${f}"
  fi
done < <(find "${DUMP_DIR}" -type f -name 'workflow.TestResult.*' -print0 2>/dev/null)

if [[ -z "${latest_dump}" ]]; then
  echo "error: no workflow.TestResult.* file found under ${DUMP_DIR}" >&2
  echo "hint: ensure SNYK_TMP_PATH is honored by the CLI build and that the" >&2
  echo "      scan workflow emits a []byte TestResult payload that exceeds" >&2
  echo "      INTERNAL_IN_MEMORY_THRESHOLD_BYTES (=1)." >&2
  if is_oss_test_scan; then
    echo "      For OSS snyk test, INTERNAL_SNYK_CLI_USE_UNIFIED_TEST_API_FOR_OS_CLI_TEST=true" >&2
    echo "      is required (generate-fixture sets it by default for test scans)." >&2
  fi
  exit 1
fi

raw_output="${OUT_DIR}/${NAME}.testresult.raw.json"
cp "${latest_dump}" "${raw_output}"
echo "wrote ${raw_output}"

if [[ "${REDACT}" == "1" ]]; then
  redacted_output="${OUT_DIR}/${NAME}.testresult.json"
  echo ""
  printf "Redacting:\n"
  printf "  cd %q\n" "${REPO_ROOT}"
  printf "  go run ./cmd/ufm-fixture-tool --input=%q --output=%q\n" "${raw_output}" "${redacted_output}"
  (
    cd "${REPO_ROOT}"
    go run ./cmd/ufm-fixture-tool --input="${raw_output}" --output="${redacted_output}"
  )
fi
