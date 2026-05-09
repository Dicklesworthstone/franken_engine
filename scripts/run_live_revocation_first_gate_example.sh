#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"
# shellcheck disable=SC1091
source "${root_dir}/scripts/lib/proof_artifact_contract.sh"

mode="${1:-ci}"
artifact_root="${LIVE_REVOCATION_FIRST_GATE_ARTIFACT_ROOT:-artifacts/live_revocation_first_gate}"
run_id="${LIVE_REVOCATION_FIRST_GATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${LIVE_REVOCATION_FIRST_GATE_RUN_DIR:-${artifact_root}/${run_id}}"
source_report_path="${run_dir}/source_report.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
rerun_command="./scripts/run_live_revocation_first_gate_example.sh ${mode}"
export RUSTC_WRAPPER="${RUSTC_WRAPPER:-}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${root_dir}/target/live_revocation_first_gate}"

if ! command -v rch >/dev/null 2>&1; then
  echo "rch is required for live revocation-first proof example Cargo execution" >&2
  exit 2
fi

cargo_command=(rch exec -- env "RUSTC_WRAPPER=${RUSTC_WRAPPER}" "CARGO_INCREMENTAL=${CARGO_INCREMENTAL}" "CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS}" "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}" cargo run -p frankenengine-engine --example live_revocation_first_gate -- "$run_dir")

mkdir -p "$run_dir"
{
  printf '%s\n' "$rerun_command"
  printf '%q ' "${cargo_command[@]}"
  printf '\n'
} >"$commands_path"

"${cargo_command[@]}"

proof_contract_write_standard_bundle \
  "$run_dir" \
  "live_revocation_first_gate_example" \
  "pass" \
  "$rerun_command" \
  "$source_report_path" \
  "$events_path" \
  "$commands_path" \
  "bd-3mp80" \
  "revocation-first-gate-live-example" \
  0

jq -e '
  .decision == "deny"
  and .signed_receipts_verified == true
  and .active_query_count_after_revocation == 0
  and .revoked_query_count_after_revocation == 1
  and ([.receipt_artifacts[].receipt_kind] | sort == ["publication", "revocation"])
' "$source_report_path" >/dev/null

jq -e '.status == "pass" and .gate_name == "live_revocation_first_gate_example"' \
  "${run_dir}/manifest.json" >/dev/null

printf 'live revocation-first proof bundle: %s\n' "$run_dir"
