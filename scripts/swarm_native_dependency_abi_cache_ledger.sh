#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_NATIVE_DEPENDENCY_ABI_CACHE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-native-dependency-abi-cache-ledger}"
run_id="${SWARM_NATIVE_DEPENDENCY_ABI_CACHE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_NATIVE_DEPENDENCY_ABI_CACHE_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_NATIVE_DEPENDENCY_ABI_CACHE_SOURCE_REVISION:-unknown}"
contract_json="${root_dir}/docs/swarm_native_dependency_abi_cache_ledger_contract_v1.json"
abi_cache_input_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_native_dependency_abi_cache_ledger.sh [OPTIONS]

Computes a deterministic native ABI fingerprint for remote validation target
reuse and emits advisory cache reuse or quarantine decisions. This script is
fixture-fed and does not run Cargo or RCH, delete target directories, mutate
workers, install packages, or change queue policy.

Required:
  --abi-cache-input-json FILE

Optional:
  --contract-json FILE
  --source-revision REV
  --output-dir DIR

Artifacts:
  native_dependency_abi_cache_ledger.json
  native_dependency_abi_cache_sources.json
  events.jsonl
  commands.txt
  summary.md

Exit codes:
  0  cached proof fingerprint matches current ABI fingerprint
  75 cached proof reuse is quarantined
  42 required ABI evidence is missing or malformed
  64 invalid invocation or missing input
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --abi-cache-input-json)
      abi_cache_input_json="${2:-}"
      shift 2
      ;;
    --contract-json)
      contract_json="${2:-}"
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

if [[ -z "$abi_cache_input_json" ]]; then
  printf 'ABI cache input JSON is required\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for native dependency ABI cache ledger\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for native dependency ABI cache ledger\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
ledger_path="${run_dir}/native_dependency_abi_cache_ledger.json"
sources_path="${run_dir}/native_dependency_abi_cache_sources.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
summary_path="${run_dir}/summary.md"
canonical_path="${run_dir}/abi_fingerprint_input.canonical.json"

input_normalized="${run_dir}/abi_cache_input.normalized.json"
contract_normalized="${run_dir}/abi_cache_contract.normalized.json"

printf './scripts/swarm_native_dependency_abi_cache_ledger.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"

normalize_required_json() {
  local input="$1"
  local output="$2"
  local label="$3"
  if [[ ! -f "$input" ]]; then
    printf 'missing required %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  if ! jq empty "$input" >/dev/null 2>&1; then
    printf 'invalid required %s JSON: %s\n' "$label" "$input" >&2
    exit 64
  fi
  jq -cS . "$input" >"$output"
}

write_event() {
  local validation_id="$1"
  local event="$2"
  local outcome="$3"
  local error_code="$4"
  local detail="$5"
  jq -nc \
    --arg schema_version "franken-engine.native-dependency-abi-cache-ledger.event.v1" \
    --arg trace_id "native-abi-cache-${validation_id}" \
    --arg validation_id "$validation_id" \
    --arg worker_id "$(jq -r '.rch_worker_id // "unknown-worker"' "$input_normalized" 2>/dev/null || printf unknown-worker)" \
    --arg dependency_id "all" \
    --arg component "swarm_native_dependency_abi_cache_ledger" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg error_code "$error_code" \
    --arg detail "$detail" \
    '{schema_version:$schema_version,trace_id:$trace_id,validation_id:$validation_id,worker_id:$worker_id,dependency_id:$dependency_id,component:$component,event:$event,outcome:$outcome,error_code:$error_code,detail:$detail}' \
    >>"$events_path"
}

normalize_required_json "$abi_cache_input_json" "$input_normalized" "ABI cache input"
normalize_required_json "$contract_json" "$contract_normalized" "ABI cache contract"

validation_id="$(jq -r '.validation_id // "unknown"' "$input_normalized")"
write_event "$validation_id" "inputs.loaded" "provided" "ok" "normalized ABI cache inputs"

jq -cS '
  {
    rust_toolchain,
    rch_worker_id,
    target_dir_id,
    requirement_bundle_version,
    native_dependencies: ((.native_dependencies // []) | sort_by(.dependency_id) | map({
      dependency_id,
      pkg_config_version,
      include_roots,
      environment_roots,
      header_paths,
      abi_fingerprint
    }))
  }
' "$input_normalized" >"$canonical_path"

current_fingerprint="$(sha256sum "$canonical_path" | awk '{print $1}')"

jq -n \
  --arg source_revision "$source_revision" \
  --arg current_fingerprint "$current_fingerprint" \
  --slurpfile input "$input_normalized" \
  --slurpfile contract "$contract_normalized" '
  ($input[0]) as $input
  | ($contract[0]) as $contract
  | ($input.cached_proof // {}) as $cached
  | ($input.native_dependencies // []) as $deps
  | ($deps | map(select((.status // "present") != "present" or (.abi_fingerprint // null) == null))) as $missing_abi
  | ($deps | map(select(((.header_paths // []) | length) == 0))) as $missing_headers
  | ($cached.abi_fingerprint // null) as $cached_fingerprint
  | ($cached.rch_worker_id // $input.rch_worker_id // null) as $cached_worker
  | (
      []
      + (if ($missing_abi | length) > 0 then ["missing_native_abi_evidence"] else [] end)
      + (if ($missing_headers | length) > 0 then ["missing_required_header_path"] else [] end)
      + (if $cached_worker != null and $cached_worker != ($input.rch_worker_id // null) then ["worker_identity_changed"] else [] end)
      + (if $cached_fingerprint != null and $cached_fingerprint != $current_fingerprint then ["target_cache_fingerprint_mismatch"] else [] end)
      + (if (($deps | map(.pkg_config_version) | unique | length) > 1) then ["native_dependency_version_changed"] else [] end)
      + (if $cached_fingerprint == $current_fingerprint and ($missing_abi | length) == 0 and ($missing_headers | length) == 0 and ($cached_worker == null or $cached_worker == ($input.rch_worker_id // null)) then ["abi_fingerprint_match"] else [] end)
      | unique
    ) as $reason_codes
  | (
      if ($missing_abi | length) > 0 or ($missing_headers | length) > 0 then "fail_closed"
      elif ($cached_fingerprint == $current_fingerprint and ($cached_worker == null or $cached_worker == ($input.rch_worker_id // null))) then "reuse_allowed"
      else "reuse_quarantined"
      end
    ) as $decision
  | {
      schema_version: $contract.output_schema_version,
      source_schema_version: $contract.source_schema_version,
      source_revision: $source_revision,
      validation_id: ($input.validation_id // "unknown"),
      rust_toolchain: ($input.rust_toolchain // null),
      rch_worker_id: ($input.rch_worker_id // null),
      target_dir_id: ($input.target_dir_id // null),
      requirement_bundle_version: ($input.requirement_bundle_version // null),
      current_abi_fingerprint: $current_fingerprint,
      cached_abi_fingerprint: $cached_fingerprint,
      cached_worker_id: $cached_worker,
      native_dependencies: $deps,
      reason_codes: $reason_codes,
      decision: $decision,
      reuse_allowed: ($decision == "reuse_allowed"),
      quarantine_reason: (if $decision == "reuse_allowed" then null else ($reason_codes | join(",")) end),
      mutation_policy: $contract.mutation_policy
    }
' >"$ledger_path"

decision="$(jq -r '.decision' "$ledger_path")"

jq -n \
  --arg schema_version "franken-engine.native-dependency-abi-cache-ledger-sources.v1" \
  --arg source_revision "$source_revision" \
  --arg abi_cache_input_json "$abi_cache_input_json" \
  --arg contract_json "$contract_json" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    inputs: {
      abi_cache_input_json: $abi_cache_input_json,
      contract_json: $contract_json
    }
  }' >"$sources_path"

{
  printf '%s\n\n' '# Native Dependency ABI Cache Ledger'
  printf '%s\n' "- validation_id: \`${validation_id}\`"
  printf '%s\n' "- decision: \`${decision}\`"
  printf '%s\n' "- current_abi_fingerprint: \`${current_fingerprint}\`"
  printf '%s\n' "- reason_codes: \`$(jq -c '.reason_codes' "$ledger_path")\`"
} >"$summary_path"

write_event "$validation_id" "ledger.completed" "$decision" "$decision" "$ledger_path"

case "$decision" in
  reuse_allowed)
    exit 0
    ;;
  reuse_quarantined)
    exit 75
    ;;
  fail_closed)
    exit 42
    ;;
  *)
    exit 42
    ;;
esac
