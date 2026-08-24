#!/usr/bin/env bash
# Pre-flight for contributor billing E2E — all five in-scope paths.
#
# Usage:
#   GAF=~/go-application-framework
#   bash "$GAF/internal/contributors/docs/scripts/cli-billing-lazy-open-preflight.sh"
#
# Optional: --path monitor-legacy|iac|code-native|code-legacy|aibom
# Optional env: GAF, CLI, CLI_ROOT, BIN, EXPECT_GAF_BRANCH, EXPECT_CLI_BRANCH
# Per-path fixtures: FIXTURE_MONITOR, FIXTURE_IAC, FIXTURE_CODE, FIXTURE_AIBOM

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GAF="${GAF:-$(cd "$SCRIPT_DIR/../../../.." && pwd)}"
GUIDE="$SCRIPT_DIR/../cli-billing-e2e.md"

SELECTED_PATH=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --path)
      SELECTED_PATH="${2:-}"
      shift 2
      ;;
    -h | --help)
      sed -n '1,15p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1 (try --path <id> or --help)" >&2
      exit 2
      ;;
  esac
done

# shellcheck source=cli-billing-lazy-open-preflight-common.sh
source "$SCRIPT_DIR/_cli-billing-lazy-open-preflight-common.sh"

PATHS=()
if [[ -n "$SELECTED_PATH" ]]; then
  if ! preflight_path_command "$SELECTED_PATH" >/dev/null; then
    echo "Unknown --path '$SELECTED_PATH'. Valid: ${PREFLIGHT_PATH_IDS[*]}" >&2
    exit 2
  fi
  PATHS=("$SELECTED_PATH")
  preflight_path_warnings "$SELECTED_PATH"
else
  PATHS=("${PREFLIGHT_PATH_IDS[@]}")
  for path_id in "${PREFLIGHT_PATH_IDS[@]}"; do
    preflight_path_warnings "$path_id"
  done
fi

if [[ -n "$SELECTED_PATH" ]]; then
  echo "Contributor billing E2E pre-flight — $(preflight_path_command "$SELECTED_PATH")"
else
  echo "Contributor billing E2E pre-flight — all in-scope paths (${#PATHS[@]})"
fi
echo ""

preflight_shared
preflight_fixtures "${PATHS[@]}"

if [[ -n "$SELECTED_PATH" ]]; then
  run_filter=$(preflight_path_middleware_tests "$SELECTED_PATH")
  preflight_middleware_tests "$run_filter" "$(preflight_path_command "$SELECTED_PATH")"
  preflight_finish "$(preflight_path_command "$SELECTED_PATH")"
else
  run_filter=$(preflight_all_middleware_tests | tr -d '\n')
  preflight_middleware_tests "$run_filter" "all five capture paths"
  preflight_finish "all ${#PATHS[@]} paths"
fi
