#!/usr/bin/env bash
set -euo pipefail

artifact_root="${PROOF_ECONOMY_CONTROL_TOWER_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-proof-economy-control-tower}"
run_id="${PROOF_ECONOMY_CONTROL_TOWER_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${PROOF_ECONOMY_CONTROL_TOWER_RUN_DIR:-${artifact_root}/${run_id}}"
proof_reuse_admission_json=""
tail_latency_rescue_json=""
agent_run_evidence_index_json=""
source_revision="${PROOF_ECONOMY_CONTROL_TOWER_SOURCE_REVISION:-}"
original_args=("$@")

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/proof_economy_control_tower.sh [OPTIONS]

Compose proof-economy control tower evidence for operator review.

Required:
  --proof-reuse-admission-json FILE   franken-engine.proof-reuse-admission-bundle.v1
  --tail-latency-rescue-json FILE     franken-engine.proof-queue-tail-latency-rescue-receipt.v1
  --agent-run-evidence-index-json FILE
                                      franken-engine.agent-run-evidence-index.v1

Optional:
  --source-revision REV
  --output-dir DIR

Artifacts:
  proof_economy_control_tower_report.json
  events.jsonl
  commands.txt
  report.md

The entry point is read-only: it does not run Cargo, invoke rch, query live
Agent Mail, mutate br, release reservations, or change queue policy.
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --proof-reuse-admission-json)
      proof_reuse_admission_json="${2:-}"
      shift 2
      ;;
    --tail-latency-rescue-json)
      tail_latency_rescue_json="${2:-}"
      shift 2
      ;;
    --agent-run-evidence-index-json)
      agent_run_evidence_index_json="${2:-}"
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
      printf 'unknown option: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for proof-economy control tower reporting\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for proof-economy control tower reporting\n' >&2
  exit 2
fi
if [[ -z "$proof_reuse_admission_json" || -z "$tail_latency_rescue_json" || -z "$agent_run_evidence_index_json" ]]; then
  printf 'proof-economy control tower requires all three component receipts\n' >&2
  usage
  exit 64
fi
for input in "$proof_reuse_admission_json" "$tail_latency_rescue_json" "$agent_run_evidence_index_json"; do
  if [[ ! -f "$input" ]]; then
    printf 'component receipt not found: %s\n' "$input" >&2
    exit 64
  fi
  if ! jq empty "$input" >/dev/null 2>&1; then
    printf 'component receipt is not valid JSON: %s\n' "$input" >&2
    exit 64
  fi
done
if ! jq -e '.schema_version == "franken-engine.proof-reuse-admission-bundle.v1"' "$proof_reuse_admission_json" >/dev/null; then
  printf 'proof reuse admission receipt has unexpected schema\n' >&2
  exit 64
fi
if ! jq -e '.schema_version == "franken-engine.proof-queue-tail-latency-rescue-receipt.v1"' "$tail_latency_rescue_json" >/dev/null; then
  printf 'tail-latency rescue receipt has unexpected schema\n' >&2
  exit 64
fi
if ! jq -e '.schema_version == "franken-engine.agent-run-evidence-index.v1"' "$agent_run_evidence_index_json" >/dev/null; then
  printf 'agent-run evidence index has unexpected schema\n' >&2
  exit 64
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
report_json="${run_dir}/proof_economy_control_tower_report.json"
report_tmp="${report_json}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_md="${run_dir}/report.md"

for artifact_path in "$report_json" "$report_tmp" "$events_path" "$commands_path" "$report_md"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/proof_economy_control_tower.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

emit_event() {
  jq -nc \
    --arg schema_version "franken-engine.proof-economy-control-tower.event.v1" \
    --arg event "$1" \
    --arg detail "$2" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event:$event,detail:$detail,source_revision:$source_revision}' >>"$events_path"
}

emit_event "control_tower_started" "loaded component receipts"

jq -n \
  --slurpfile reuse "$proof_reuse_admission_json" \
  --slurpfile tail "$tail_latency_rescue_json" \
  --slurpfile evidence "$agent_run_evidence_index_json" \
  --arg schema_version "franken-engine.proof-economy-control-tower-report.v1" \
  --arg source_revision "$source_revision" \
  --arg proof_reuse_admission_json "$proof_reuse_admission_json" \
  --arg tail_latency_rescue_json "$tail_latency_rescue_json" \
  --arg agent_run_evidence_index_json "$agent_run_evidence_index_json" \
  --arg report_json "proof_economy_control_tower_report.json" \
  --arg events_jsonl "events.jsonl" \
  --arg commands_txt "commands.txt" \
  --arg report_md "report.md" \
  '
  def component($id; $decision; $path; $summary):
    {
      component_id:$id,
      decision:$decision,
      evidence_path:$path,
      summary:$summary
    };
  def fail_decision($d): ["fail_closed","fail_closed_advisory"] | index($d) != null;
  def degraded_decision($d): ["degraded","advisory","refresh_required","partial_refresh_required"] | index($d) != null;
  [
    component(
      "proof_reuse_admission";
      ($reuse[0].admission_decision // "unknown");
      $proof_reuse_admission_json;
      {
        reusable_count:([($reuse[0].admission_rows // [])[]? | select(.classification == "reusable")] | length),
        refresh_required_count:([($reuse[0].admission_rows // [])[]? | select(.classification == "refresh_required")] | length),
        invalid_count:([($reuse[0].admission_rows // [])[]? | select(.classification == "invalid")] | length),
        unknown_count:([($reuse[0].admission_rows // [])[]? | select(.classification == "unknown")] | length)
      }
    ),
    component(
      "tail_latency_rescue";
      ($tail[0].decision // "unknown");
      $tail_latency_rescue_json;
      {
        recommendation_count:(($tail[0].rescue_recommendations // []) | length),
        tail_latency_state:($tail[0].tail_latency_context.state // "unknown")
      }
    ),
    component(
      "agent_run_evidence_index";
      ($evidence[0].decision // "unknown");
      $agent_run_evidence_index_json;
      {
        edge_count:($evidence[0].summary.edge_count // 0),
        missing_edge_count:($evidence[0].summary.missing_edge_count // 0),
        degraded_edge_count:($evidence[0].summary.degraded_edge_count // 0)
      }
    )
  ] as $components
  | (if any($components[]; fail_decision(.decision)) then "fail_closed"
     elif any($components[]; degraded_decision(.decision)) then "degraded"
     else "pass" end) as $decision
  | {
      schema_version:$schema_version,
      source_revision:$source_revision,
      decision:$decision,
      components:$components,
      operator_entrypoint:{
        command:"./scripts/proof_economy_control_tower.sh",
        help_flag:"--help",
        mode:"documented_script_wrapper"
      },
      replay_inputs:{
        proof_reuse_admission_json:$proof_reuse_admission_json,
        tail_latency_rescue_json:$tail_latency_rescue_json,
        agent_run_evidence_index_json:$agent_run_evidence_index_json
      },
      mutation_policy:{
        fixture_fed_only:true,
        proof_only:true,
        advisory_only:true,
        queries_live_agent_mail:false,
        mutates_br:false,
        releases_reservations:false,
        sends_agent_mail:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false
      },
      artifact_paths:{
        proof_economy_control_tower_report_json:$report_json,
        events_jsonl:$events_jsonl,
        commands_txt:$commands_txt,
        report_md:$report_md
      }
    }
  ' >"$report_tmp"

report_hash="$(jq -cS '{source_revision,decision,components,replay_inputs}' "$report_tmp" | sha256sum | awk '{print substr($1, 1, 16)}')"
jq --arg report_id "proof-economy-control-tower-${report_hash}" '. + {report_id:$report_id}' "$report_tmp" >"$report_json"

decision="$(jq -r '.decision' "$report_json")"
emit_event "control_tower_reported" "$decision"

{
  printf '# Proof Economy Control Tower\n\n'
  printf -- "- report_id: \`%s\`\n" "$(jq -r '.report_id' "$report_json")"
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- components: \`%s\`\n" "$(jq '.components | length' "$report_json")"
  printf '\n## Components\n\n'
  jq -r '.components[] | "- `" + .component_id + "`: `" + .decision + "`"' "$report_json"
} >"$report_md"

printf 'proof_economy_control_tower_report=%s\n' "$report_json"
printf 'proof_economy_control_tower_decision=%s\n' "$decision"
if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
