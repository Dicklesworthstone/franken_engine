#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_CONTROL_SURFACE_DRIFT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-control-surface-drift}"
run_id="${SWARM_CONTROL_SURFACE_DRIFT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_CONTROL_SURFACE_DRIFT_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

catalog_json=""
script_inventory_json=""
bead_status_json=""
workspace_root="$root_dir"
source_revision="${SWARM_CONTROL_SURFACE_DRIFT_SOURCE_REVISION:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_control_surface_drift_gate.sh --catalog-json FILE [OPTIONS]

Detect drift, duplicate capability, and unsafe mutation claims in a normalized
SWARM-CTRL-XVII control-surface catalog. This gate is artifact-fed and does not
query live br, Agent Mail, rch, cargo, git, or workers.

Required:
  --catalog-json FILE

Optional:
  --script-inventory-json FILE
  --bead-status-json FILE
  --workspace-root DIR
  --source-revision REV
  --output-dir DIR

Artifacts:
  control_surface_drift_report.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  no fail-closed drift detected
  42 fail-closed drift detected
  64 invalid arguments or malformed input JSON
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --catalog-json)
      catalog_json="${2:-}"
      shift 2
      ;;
    --script-inventory-json)
      script_inventory_json="${2:-}"
      shift 2
      ;;
    --bead-status-json)
      bead_status_json="${2:-}"
      shift 2
      ;;
    --workspace-root)
      workspace_root="${2:-}"
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

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for control-surface drift gating\n' >&2
  exit 2
fi
if [[ -z "$catalog_json" ]]; then
  printf '--catalog-json is required\n' >&2
  usage
  exit 64
fi
for input in "$catalog_json" "$script_inventory_json" "$bead_status_json"; do
  if [[ -n "$input" ]]; then
    if [[ ! -f "$input" ]]; then
      printf 'input file does not exist: %s\n' "$input" >&2
      exit 64
    fi
    if ! jq empty "$input" >/dev/null 2>&1; then
      printf 'input is not valid JSON: %s\n' "$input" >&2
      exit 64
    fi
  fi
done
if [[ ! -d "$workspace_root" ]]; then
  printf 'workspace root does not exist: %s\n' "$workspace_root" >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
report_path="${run_dir}/control_surface_drift_report.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
markdown_path="${run_dir}/report.md"
findings_jsonl="${run_dir}/findings.jsonl"
remediation_jsonl="${run_dir}/remediation.jsonl"
catalog_scripts_path="${run_dir}/catalog_scripts.txt"
inventory_scripts_path="${run_dir}/inventory_scripts.txt"

: >"$events_path"
: >"$findings_jsonl"
: >"$remediation_jsonl"
: >"$catalog_scripts_path"
: >"$inventory_scripts_path"

printf './scripts/swarm_control_surface_drift_gate.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-control-surface-drift.event.v1" \
    --arg event_name "$1" \
    --arg detail "$2" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event_name:$event_name,detail:$detail,source_revision:$source_revision}' >>"$events_path"
}

fail_closed_count=0

append_finding() {
  local code="$1"
  local surface_id="$2"
  local detail="$3"
  local remediation="$4"

  jq -nc \
    --arg severity "fail_closed" \
    --arg code "$code" \
    --arg surface_id "$surface_id" \
    --arg detail "$detail" \
    '{severity:$severity,code:$code,surface_id:$surface_id,detail:$detail}' >>"$findings_jsonl"
  jq -nc \
    --arg code "$code" \
    --arg surface_id "$surface_id" \
    --arg command "$remediation" \
    '{code:$code,surface_id:$surface_id,command:$command}' >>"$remediation_jsonl"
  fail_closed_count=$((fail_closed_count + 1))
  write_event "fail_closed" "${surface_id}:${code}:${detail}"
}

if ! jq -e '(.surfaces | type == "array") and (.decision | type == "string")' "$catalog_json" >/dev/null; then
  printf 'catalog JSON must contain decision and surfaces array\n' >&2
  exit 64
fi

catalog_decision="$(jq -r '.decision' "$catalog_json")"
if [[ "$catalog_decision" == "fail_closed" ]]; then
  append_finding "FE-SWARM-DRIFT-UPSTREAM-CATALOG-FAIL-CLOSED" "catalog" "upstream normalized catalog is fail_closed" "Fix upstream catalog findings before routing or intake work."
fi

jq -r '.surfaces[] | .implementation_script?, .smoke_script? | select(. != null)' "$catalog_json" \
  | sort -u >"$catalog_scripts_path"

if [[ -n "$script_inventory_json" ]]; then
  jq -r '
    if type == "array" then .[]
    elif has("scripts") then .scripts[]
    elif has("paths") then .paths[]
    else empty end
    | if type == "object" then .path else . end
    | select(type == "string")
  ' "$script_inventory_json" | sort -u >"$inventory_scripts_path"

  while IFS= read -r script_path; do
    [[ -z "$script_path" ]] && continue
    if ! grep -Fxq "$script_path" "$catalog_scripts_path"; then
      append_finding "FE-SWARM-DRIFT-UNCATALOGED-SCRIPT" "$script_path" "script inventory path is absent from catalog" "Add ${script_path} to docs/swarm_control_surface_catalog_contract_v1.json or explicitly exclude it from the inventory."
    fi
  done <"$inventory_scripts_path"
fi

jq -r '
  .surfaces[]
  | .surface_id as $surface
  | (.intent_tags // [])[]
  | [$surface, .]
  | @tsv
' "$catalog_json" >"${run_dir}/intent_pairs.tsv"

cut -f2 "${run_dir}/intent_pairs.tsv" | sort | uniq -d >"${run_dir}/duplicate_intents.txt"
while IFS= read -r intent; do
  [[ -z "$intent" ]] && continue
  mapfile -t surfaces < <(awk -v intent="$intent" '$2 == intent {print $1}' "${run_dir}/intent_pairs.tsv" | sort -u)
  for ((i = 0; i < ${#surfaces[@]}; i++)); do
    for ((j = i + 1; j < ${#surfaces[@]}; j++)); do
      left="${surfaces[$i]}"
      right="${surfaces[$j]}"
      if ! jq -e --arg left "$left" --arg right "$right" '
        .surfaces[]
        | select(.surface_id == $left)
        | ((.upstream_surface_ids // []) + (.downstream_surface_ids // []))
        | index($right) != null
      ' "$catalog_json" >/dev/null \
        && ! jq -e --arg left "$left" --arg right "$right" '
          .surfaces[]
          | select(.surface_id == $right)
          | ((.upstream_surface_ids // []) + (.downstream_surface_ids // []))
          | index($left) != null
        ' "$catalog_json" >/dev/null; then
        append_finding "FE-SWARM-DRIFT-DUPLICATE-INTENT" "${left},${right}" "shared intent tag without relationship: ${intent}" "Declare an upstream/downstream relation or split the intent tags for ${left} and ${right}."
      fi
    done
  done
done <"${run_dir}/duplicate_intents.txt"

surface_count="$(jq '.surfaces | length' "$catalog_json")"
for ((idx = 0; idx < surface_count; idx++)); do
  row="$(jq -c ".surfaces[$idx]" "$catalog_json")"
  surface_id="$(jq -r '.surface_id // "unknown"' <<<"$row")"

  if jq -e '
    (.mutation_policy // {}) as $m
    | any([
        "mutates_br",
        "claims_beads",
        "reassigns_beads",
        "closes_beads",
        "releases_reservations",
        "sends_agent_mail",
        "queries_live_agent_mail",
        "mutates_git",
        "runs_cargo",
        "runs_rch",
        "mutates_remote_workers",
        "changes_live_queue_policy",
        "replaces_operator_status_report"
      ][]; $m[.] == true)
  ' <<<"$row" >/dev/null; then
    append_finding "FE-SWARM-DRIFT-MUTATION-POLICY-CONTRADICTION" "$surface_id" "catalog row contains unsupported mutation policy" "Keep ${surface_id} advisory-only or move live mutation claims to a separate reviewed bead."
  fi

  if jq -e '
    [.validation_commands[]? | select(
      test("(^|[[:space:]])cargo (check|test|clippy|run)")
      and (startswith("rch exec -- env CARGO_TARGET_DIR=") | not)
    )] | length > 0
  ' <<<"$row" >/dev/null; then
    append_finding "FE-SWARM-DRIFT-BARE-HEAVY-CARGO" "$surface_id" "validation_commands contain bare heavy Cargo" "Wrap heavy Cargo examples with rch exec -- env CARGO_TARGET_DIR=."
  fi

  smoke_script="$(jq -r '.smoke_script // empty' <<<"$row")"
  if [[ -n "$smoke_script" && -f "${workspace_root}/${smoke_script}" ]]; then
    if ! grep -Eq '(^|[[:space:]])check\)' "${workspace_root}/${smoke_script}" \
      || ! grep -Eq '(^|[[:space:]])selftest\)' "${workspace_root}/${smoke_script}"; then
      append_finding "FE-SWARM-DRIFT-SMOKE-MISSING-MODE" "$surface_id" "smoke script lacks check or selftest mode" "Add check and selftest modes to ${smoke_script}."
    fi
  fi

  if [[ -n "$bead_status_json" ]]; then
    owner="$(jq -r '.owning_bead_id // empty' <<<"$row")"
    if [[ -n "$owner" ]]; then
      owner_status="$(jq -r --arg owner "$owner" '
        if type == "array" then (.[] | select(.id == $owner) | .status) // empty
        elif has("issues") then (.issues[] | select(.id == $owner) | .status) // empty
        else empty end
      ' "$bead_status_json")"
      if [[ -n "$owner_status" && "$owner_status" != "closed" ]]; then
        append_finding "FE-SWARM-DRIFT-STALE-OWNER-BEAD" "$surface_id" "owning bead ${owner} is ${owner_status}" "Close ${owner} or point ${surface_id} at the bead that actually shipped it."
      fi
    fi
  fi
done

if [[ "$fail_closed_count" -gt 0 ]]; then
  decision="fail_closed"
  exit_code=42
else
  decision="pass"
  exit_code=0
fi

jq -s . "$findings_jsonl" >"${run_dir}/findings.json"
jq -s . "$remediation_jsonl" >"${run_dir}/remediation.json"

# shellcheck disable=SC2094
jq -n \
  --arg schema_version "franken-engine.swarm-control-surface-drift-report.v1" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg catalog_json "$catalog_json" \
  --arg report_json "$report_path" \
  --arg events_jsonl "$events_path" \
  --arg commands_txt "$commands_path" \
  --arg report_md "$markdown_path" \
  --argjson fail_closed_count "$fail_closed_count" \
  --slurpfile findings "${run_dir}/findings.json" \
  --slurpfile remediation "${run_dir}/remediation.json" \
  '{
    schema_version: $schema_version,
    source_revision: $source_revision,
    decision: $decision,
    catalog_json: $catalog_json,
    fail_closed_count: $fail_closed_count,
    findings: $findings[0],
    remediation_commands: $remediation[0],
    artifact_paths: {
      control_surface_drift_report_json: $report_json,
      events_jsonl: $events_jsonl,
      commands_txt: $commands_txt,
      report_md: $report_md
    },
    mutation_policy: {
      advisory_only: true,
      proof_only: true,
      fixture_fed_only: true,
      mutates_br: false,
      sends_agent_mail: false,
      runs_cargo: false,
      runs_rch: false,
      changes_live_queue_policy: false
    }
  }' >"$report_path"

{
  printf '# Swarm Control-Surface Drift Gate\n\n'
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- fail_closed findings: \`%s\`\n" "$fail_closed_count"
  printf -- "- report: \`%s\`\n" "$report_path"
} >"$markdown_path"

write_event "drift_report_emitted" "$decision"
exit "$exit_code"
