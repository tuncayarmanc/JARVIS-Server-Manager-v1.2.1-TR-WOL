#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf -- "$TMP"' EXIT

run_case() {
  local helper_state="$1" sudoers_state="$2" failpoint="$3" case_dir="$TMP/$helper_state-$sudoers_state-${failpoint:-commit}"
  mkdir -p "$case_dir/bin" "$case_dir/sudoers"
  [[ "$helper_state" == present ]] && printf 'old-helper\n' > "$case_dir/bin/helper"
  [[ "$sudoers_state" == present ]] && printf 'old-sudoers\n' > "$case_dir/sudoers/policy"
  set +e
  JARVIS_INSTALL_TEST_MODE=1 JARVIS_INSTALL_FAILPOINT="$failpoint" JARVIS_HELPER_PATH="$case_dir/bin/helper" JARVIS_SUDOERS_PATH="$case_dir/sudoers/policy" JARVIS_TARGET_USER=tester bash -c '
    set -euo pipefail
    source "$1/server-setup/install-jarvis-remediation.sh"
    validate_sudoers() { grep -q "NOPASSWD" "$1"; }
    safe_parent() { return 0; }
    transaction_install "$1/helper.sh"
  ' bash "$ROOT" > "$case_dir/out" 2>&1
  local rc=$?
  set -e
  if [[ -n "$failpoint" ]]; then
    [[ "$rc" -ne 0 ]]
    [[ "$helper_state" == absent ]] && [[ ! -e "$case_dir/bin/helper" ]] || [[ "$(<"$case_dir/bin/helper")" == old-helper ]]
    [[ "$sudoers_state" == absent ]] && [[ ! -e "$case_dir/sudoers/policy" ]] || [[ "$(<"$case_dir/sudoers/policy")" == old-sudoers ]]
  else
    [[ "$rc" -eq 0 ]]
    grep -q 'HELPER_VERSION=1.2.2' "$case_dir/bin/helper"
    grep -q 'NOPASSWD' "$case_dir/sudoers/policy"
  fi
}

for helper_state in absent present; do
  for sudoers_state in absent present; do
    run_case "$helper_state" "$sudoers_state" ''
    run_case "$helper_state" "$sudoers_state" after_helper
    run_case "$helper_state" "$sudoers_state" after_sudoers
    run_case "$helper_state" "$sudoers_state" after_final_validation
  done
done
printf 'transaction matrix passed\n'
