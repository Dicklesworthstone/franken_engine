#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_NATIVE_DEPENDENCY_OPERATOR_STATUS_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-native-dependency-operator-status}"
run_id="${SWARM_NATIVE_DEPENDENCY_OPERATOR_STATUS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_NATIVE_DEPENDENCY_OPERATOR_STATUS_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_NATIVE_DEPENDENCY_OPERATOR_STATUS_SOURCE_REVISION:-unknown}"
route_advisory_json=""
abi_cache_ledger_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_native_dependency_operator_status.sh [OPTIONS]

Formats native dependency route planner and ABI cache ledger evidence into
operator status, Agent Mail handoff, and br closeout snippets. This script is
fixture-fed and does not run Cargo or RCH, mutate workers, install packages,
delete target directories, reroute live tasks, update beads, or send Agent Mail.

Required:
  --route-advisory-json FILE
  --abi-cache-ledger-json FILE

Optional:
  --source-revision REV
  --output-dir DIR
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --route-advisory-json)
      route_advisory_json="${2:-}"
      shift 2
      ;;
    --abi-cache-ledger-json)
      abi_cache_ledger_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --output-dir)
      run_dir="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if [[ -z "$route_advisory_json" || -z "$abi_cache_ledger_json" ]]; then
  printf 'route advisory and ABI cache ledger JSON are required\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for native dependency operator status\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
status_md="${run_dir}/native_dependency_operator_status.md"
handoff_md="${run_dir}/agent_mail_handoff.md"
closeout_md="${run_dir}/br_closeout_snippet.md"
status_json="${run_dir}/native_dependency_operator_status.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"

printf './scripts/swarm_native_dependency_operator_status.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"

normalize_json() {
  local input="$1"
  local label="$2"
  if [[ ! -f "$input" ]]; then
    printf 'missing %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  if ! jq empty "$input" >/dev/null 2>&1; then
    printf 'invalid %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
}

write_event() {
  local validation_id="$1"
  local event="$2"
  local outcome="$3"
  local error_code="$4"
  jq -nc \
    --arg schema_version "franken-engine.native-dependency-operator-status.event.v1" \
    --arg trace_id "native-dependency-operator-status-${validation_id}" \
    --arg validation_id "$validation_id" \
    --arg worker_id "not_applicable" \
    --arg dependency_id "all" \
    --arg component "swarm_native_dependency_operator_status" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    '{schema_version:$schema_version,trace_id:$trace_id,validation_id:$validation_id,worker_id:$worker_id,dependency_id:$dependency_id,component:$component,event:$event,outcome:$outcome,error_code:$error_code}' \
    >>"$events_path"
}

normalize_json "$route_advisory_json" "route advisory"
normalize_json "$abi_cache_ledger_json" "ABI cache ledger"

validation_id="$(jq -r '.validation_id // "unknown"' "$route_advisory_json")"
route_decision="$(jq -r '.decision // "unknown"' "$route_advisory_json")"
route_truth="$(jq -r '.truth_state // "unknown"' "$route_advisory_json")"
abi_decision="$(jq -r '.decision // "unknown"' "$abi_cache_ledger_json")"
compatible_workers="$(jq -r '(.compatible_worker_ids // []) | join(",")' "$route_advisory_json")"
incompatible_workers="$(jq -r '(.incompatible_workers // []) | map(.worker_id + ":" + ((.missing_required_dependency_ids // []) | join("+"))) | join(",")' "$route_advisory_json")"
fail_closed_workers="$(jq -r '(.fail_closed_workers // []) | map(.worker_id + ":" + ((.reason_codes // []) | join("+"))) | join(",")' "$route_advisory_json")"
route_reasons="$(jq -r '(.reason_codes // []) | join(",")' "$route_advisory_json")"
abi_reasons="$(jq -r '(.reason_codes // []) | join(",")' "$abi_cache_ledger_json")"
preferred_worker="$(jq -r '.retry_advice.preferred_worker_id // "none"' "$route_advisory_json")"

status_label="FAIL-CLOSED"
case "$route_decision:$abi_decision" in
  pass:reuse_allowed)
    status_label="PASS"
    ;;
  pass:reuse_quarantined|blocked:*|pass:fail_closed)
    status_label="BLOCKED"
    ;;
  fail_closed:*)
    status_label="FAIL-CLOSED"
    ;;
esac

jq -n \
  --arg schema_version "franken-engine.native-dependency-operator-status.v1" \
  --arg source_revision "$source_revision" \
  --arg validation_id "$validation_id" \
  --arg status "$status_label" \
  --arg route_decision "$route_decision" \
  --arg route_truth "$route_truth" \
  --arg abi_decision "$abi_decision" \
  --arg compatible_workers "$compatible_workers" \
  --arg incompatible_workers "$incompatible_workers" \
  --arg fail_closed_workers "$fail_closed_workers" \
  --arg route_reasons "$route_reasons" \
  --arg abi_reasons "$abi_reasons" \
  --arg preferred_worker "$preferred_worker" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    validation_id: $validation_id,
    status: $status,
    route_decision: $route_decision,
    route_truth: $route_truth,
    abi_decision: $abi_decision,
    preferred_worker: $preferred_worker,
    compatible_workers: ($compatible_workers | split(",") | map(select(length > 0))),
    incompatible_workers: ($incompatible_workers | split(",") | map(select(length > 0))),
    fail_closed_workers: ($fail_closed_workers | split(",") | map(select(length > 0))),
    route_reasons: ($route_reasons | split(",") | map(select(length > 0))),
    abi_reasons: ($abi_reasons | split(",") | map(select(length > 0))),
    advisory_only: true,
    source_failure_claimed: false
  }' >"$status_json"

{
  printf '%s\n\n' '# Native Dependency Operator Status'
  printf '%s\n' "- validation_id: \`${validation_id}\`"
  printf '%s\n' "- status: \`${status_label}\`"
  printf '%s\n' "- route_decision: \`${route_decision}\`"
  printf '%s\n' "- route_truth: \`${route_truth}\`"
  printf '%s\n' "- abi_cache_decision: \`${abi_decision}\`"
  printf '%s\n' "- preferred_worker: \`${preferred_worker}\`"
  printf '%s\n' "- compatible_workers: \`${compatible_workers:-none}\`"
  printf '%s\n' "- incompatible_workers: \`${incompatible_workers:-none}\`"
  printf '%s\n' "- fail_closed_workers: \`${fail_closed_workers:-none}\`"
  printf '%s\n' "- route_reasons: \`${route_reasons:-none}\`"
  printf '%s\n' "- abi_reasons: \`${abi_reasons:-none}\`"
  printf '\n%s\n' 'Validation environment blocker: required native dependency evidence is missing or unsafe for the selected worker. This is not evidence that the source patch failed.'
} >"$status_md"

{
  printf 'Native dependency validation `%s`: `%s`.\n\n' "$validation_id" "$status_label"
  printf 'Preferred worker: `%s`.\n' "$preferred_worker"
  printf 'Rejected workers: `%s`.\n' "${incompatible_workers:-none}"
  printf 'Fail-closed workers: `%s`.\n' "${fail_closed_workers:-none}"
  printf 'Reason codes: `%s` / `%s`.\n\n' "${route_reasons:-none}" "${abi_reasons:-none}"
  printf '%s\n' 'This is a validation environment blocker, not a source failure claim. No worker mutation or package installation was performed.'
} >"$handoff_md"

{
  printf 'Native dependency routing status: %s. Preferred worker: %s. Rejected workers: %s. Fail-closed workers: %s. Reason codes: route=%s abi=%s. Validation environment blocker; no source failure claimed.\n' \
    "$status_label" "$preferred_worker" "${incompatible_workers:-none}" "${fail_closed_workers:-none}" "${route_reasons:-none}" "${abi_reasons:-none}"
} >"$closeout_md"

write_event "$validation_id" "operator_status.generated" "$status_label" "$route_decision"

case "$status_label" in
  PASS)
    exit 0
    ;;
  BLOCKED)
    exit 75
    ;;
  FAIL-CLOSED)
    exit 42
    ;;
  *)
    exit 42
    ;;
esac
