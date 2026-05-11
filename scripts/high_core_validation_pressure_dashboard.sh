#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${HIGH_CORE_VALIDATION_PRESSURE_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-high-core-validation-pressure-dashboard}"
run_id="${HIGH_CORE_VALIDATION_PRESSURE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${HIGH_CORE_VALIDATION_PRESSURE_RUN_DIR:-${artifact_root}/${run_id}}"
source_revision="${HIGH_CORE_VALIDATION_PRESSURE_SOURCE_REVISION:-}"
case_id="manual"
original_args=("$@")

resource_envelope_json=""
rch_jobs_json=""
process_counts_json=""
proof_shard_plan_json=""
br_readiness_json=""
mail_health_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/high_core_validation_pressure_dashboard.sh --resource-envelope-json FILE --rch-jobs-json FILE --process-counts-json FILE --proof-shard-plan-json FILE --br-readiness-json FILE --mail-health-json FILE [OPTIONS]

Builds a deterministic high-core validation pressure dashboard from preserved
snapshots. It is advisory only: it does not query live br, Agent Mail, rch,
Cargo, ps, df, workers, or mutate queues.

Required snapshots:
  --resource-envelope-json FILE   Host/resource envelope or capacity snapshot.
  --rch-jobs-json FILE            Active RCH job/process snapshot.
  --process-counts-json FILE      Local cargo/rustc process count snapshot.
  --proof-shard-plan-json FILE    Proof shard plan or validation plan snapshot.
  --br-readiness-json FILE        br ready/open/in-progress summary snapshot.
  --mail-health-json FILE         Agent Mail health snapshot or captured error.

Options:
  --case-id ID
  --source-revision REV
  --output-dir DIR

Artifacts:
  high_core_validation_pressure_dashboard.json
  high_core_validation_pressure_dashboard.md
  commands.txt
  events.jsonl
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --resource-envelope-json)
      resource_envelope_json="${2:-}"
      shift 2
      ;;
    --rch-jobs-json)
      rch_jobs_json="${2:-}"
      shift 2
      ;;
    --process-counts-json)
      process_counts_json="${2:-}"
      shift 2
      ;;
    --proof-shard-plan-json)
      proof_shard_plan_json="${2:-}"
      shift 2
      ;;
    --br-readiness-json)
      br_readiness_json="${2:-}"
      shift 2
      ;;
    --mail-health-json)
      mail_health_json="${2:-}"
      shift 2
      ;;
    --case-id)
      case_id="${2:-}"
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

if [[ -z "$resource_envelope_json" || -z "$rch_jobs_json" || -z "$process_counts_json" \
  || -z "$proof_shard_plan_json" || -z "$br_readiness_json" || -z "$mail_health_json" ]]; then
  printf 'high-core validation pressure dashboard requires all six snapshot JSON inputs\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for high-core validation pressure dashboard generation\n' >&2
  exit 2
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

validate_json() {
  local path="$1"
  local label="$2"
  if [[ ! -f "$path" ]]; then
    printf 'missing %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'invalid %s JSON: %s\n' "$label" "$path" >&2
    exit 64
  fi
}

validate_json "$resource_envelope_json" "resource envelope"
validate_json "$rch_jobs_json" "RCH jobs"
validate_json "$process_counts_json" "process counts"
validate_json "$proof_shard_plan_json" "proof shard plan"
validate_json "$br_readiness_json" "br readiness"
validate_json "$mail_health_json" "mail health"

mkdir -p "$run_dir"
dashboard_path="${run_dir}/high_core_validation_pressure_dashboard.json"
report_path="${run_dir}/high_core_validation_pressure_dashboard.md"
commands_path="${run_dir}/commands.txt"
events_path="${run_dir}/events.jsonl"

resource_normalized="${run_dir}/resource_envelope.normalized.json"
rch_normalized="${run_dir}/rch_jobs.normalized.json"
process_normalized="${run_dir}/process_counts.normalized.json"
proof_normalized="${run_dir}/proof_shard_plan.normalized.json"
br_normalized="${run_dir}/br_readiness.normalized.json"
mail_normalized="${run_dir}/mail_health.normalized.json"

for artifact_path in "$dashboard_path" "$report_path" "$commands_path" "$events_path" \
  "$resource_normalized" "$rch_normalized" "$process_normalized" "$proof_normalized" \
  "$br_normalized" "$mail_normalized"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

jq -cS . "$resource_envelope_json" >"$resource_normalized"
jq -cS . "$rch_jobs_json" >"$rch_normalized"
jq -cS . "$process_counts_json" >"$process_normalized"
jq -cS . "$proof_shard_plan_json" >"$proof_normalized"
jq -cS . "$br_readiness_json" >"$br_normalized"
jq -cS . "$mail_health_json" >"$mail_normalized"

: >"$events_path"
printf './scripts/high_core_validation_pressure_dashboard.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

jq -nc --arg event "started" --arg case_id "$case_id" --arg artifact "$dashboard_path" \
  '{event:$event, case_id:$case_id, artifact:$artifact}' >>"$events_path"

# shellcheck disable=SC2094 # The output path is embedded as dashboard data; jq does not read it.
jq -S -n \
  --slurpfile resource "$resource_normalized" \
  --slurpfile rch "$rch_normalized" \
  --slurpfile process "$process_normalized" \
  --slurpfile proof "$proof_normalized" \
  --slurpfile br "$br_normalized" \
  --slurpfile mail "$mail_normalized" \
  --arg schema_version "franken-engine.high-core-validation-pressure-dashboard.v2" \
  --arg bead_id "bd-f7zfw" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg dashboard_path "$dashboard_path" \
  --arg report_path "$report_path" \
  --arg commands_path "$commands_path" \
  --arg events_path "$events_path" \
  '
  def arr($v): if ($v | type) == "array" then $v else [] end;
  def doc($v): if ($v | type) == "array" then ($v[0] // {}) else ($v // {}) end;
  def rows($v; $key): if (doc($v) | type) == "array" then doc($v) else arr(doc($v)[$key]) end;
  def low($v): ($v // "" | tostring | ascii_downcase);
  def num($v; $default): try ($v | tonumber) catch $default;
  def is_bad_state($v):
    low($v) | IN("blocked","brownout","fail_closed","failed","saturated","contaminated");
  def is_degraded_state($v):
    low($v) | IN("degraded","warning","red","error","corrupt","recovering");
  def resource_doc: doc($resource);
  def rch_doc: doc($rch);
  def process_doc: doc($process);
  def proof_doc: doc($proof);
  def br_doc: doc($br);
  def mail_doc: doc($mail);
  def active_rch_jobs:
    rows($rch; "jobs")
    | map({
        job_id:(.job_id // .pid // .id // ""),
        command:(.command // .cmd // ""),
        status:(.status // "unknown"),
        owner:(.owner // .agent // null)
      })
    | map(select((low(.status) | IN("done","complete","completed","exited","idle")) | not));
  def all_rch_jobs:
    rows($rch; "jobs")
    | map({
        job_id:(.job_id // .pid // .id // ""),
        command:(.command // .cmd // ""),
        status:(.status // "unknown"),
        owner:(.owner // .agent // null)
      });
  def proof_shards:
    rows($proof; "shards")
    | map({
        shard_id:(.shard_id // .id // .name // ""),
        status:(.status // "unknown"),
        cost_class:(.cost_class // .cost // "unknown"),
        command:(.command // null)
      });
  def ready_shards:
    proof_shards | map(select(low(.status) | IN("ready","planned","cached","available","pass","passed","ok")));
  def ready_items:
    if (br_doc | type) == "array" then br_doc
    else arr(br_doc.ready // br_doc.issues // br_doc.items)
    end;
  def resource_decision:
    low(resource_doc.decision // resource_doc.capacity_decision // resource_doc.status // resource_doc.summary.decision // "unknown");
  def memory_state:
    low(resource_doc.memory_state // resource_doc.memory.state // resource_doc.capacity.memory.state // resource_doc.summary.memory_state // "unknown");
  def disk_state:
    low(resource_doc.disk_state // resource_doc.disk.state // resource_doc.capacity.disk.state // resource_doc.summary.disk_state // "unknown");
  def rch_resource_state:
    low(resource_doc.rch_state // resource_doc.rch.state // resource_doc.capacity.rch.state // resource_doc.summary.rch_state // "unknown");
  def active_rch_count:
    num((rch_doc.active_count // rch_doc.summary.active_count // rch_doc.capacity.active_count); (active_rch_jobs | length));
  def max_rch_active:
    num((rch_doc.max_active // rch_doc.capacity.max_active // rch_doc.summary.max_active); 2);
  def cargo_count:
    num((process_doc.cargo_count // process_doc.processes.cargo // 0); 0);
  def rustc_count:
    num((process_doc.rustc_count // process_doc.processes.rustc // 0); 0);
  def local_compile_count:
    num((process_doc.cargo_rustc_count // process_doc.active_compile_count); (cargo_count + rustc_count));
  def max_local_compile:
    num((process_doc.max_local_compile_count // process_doc.thresholds.max_local_compile_count); 2);
  def ready_count:
    num((br_doc.ready_count // br_doc.total_ready // br_doc.summary.ready_count); (ready_items | length));
  def open_count:
    num((br_doc.open_count // br_doc.summary.open_count); ready_count);
  def mail_status:
    low(mail_doc.status // mail_doc.health_level // mail_doc.recovery.mode // "unknown");
  def mail_decision:
    if mail_status | IN("ok","green","healthy","available") then "available"
    elif mail_status | IN("missing","unknown") then "missing_optional"
    else "degraded" end;
  def proof_decision:
    low(proof_doc.decision // proof_doc.status // proof_doc.summary.decision // "unknown");
  def proof_stale:
    (proof_doc.stale // proof_doc.summary.stale // false) == true;

  (resource_decision | is_bad_state(.)) as $resource_decision_bad
  | ([memory_state, disk_state, rch_resource_state] | any(.[]; is_bad_state(.))) as $resource_state_bad
  | (active_rch_count >= max_rch_active or is_bad_state(rch_doc.status // rch_doc.decision // rch_resource_state)) as $rch_saturated
  | (local_compile_count > max_local_compile) as $local_contention
  | (ready_count == 0) as $zero_ready
  | (proof_stale or (proof_decision | is_bad_state(.)) or ((ready_shards | length) == 0)) as $proof_bad
  | (mail_decision == "degraded") as $mail_degraded
  | ([
      if $resource_decision_bad or $resource_state_bad then {code:"HCVD2-RESOURCE-ENVELOPE-BLOCKED", detail:"Host resource envelope is blocked, saturated, brownout, or contaminated"} else empty end,
      if $rch_saturated then {code:"HCVD2-RCH-SATURATED", detail:"Active RCH jobs meet or exceed the supplied safe active-job budget"} else empty end,
      if $local_contention then {code:"HCVD2-LOCAL-CARGO-CONTENTION", detail:"Local cargo/rustc count exceeds the cheap-check threshold"} else empty end,
      if $zero_ready then {code:"HCVD2-ZERO-READY-BEADS", detail:"No ready beads were supplied, so heavy proof admission would be unactionable"} else empty end,
      if $proof_bad then {code:"HCVD2-PROOF-PLAN-BLOCKED", detail:"Proof shard plan is stale, blocked, or has no reusable ready shards"} else empty end,
      if $mail_degraded then {code:"HCVD2-MAIL-DEGRADED", detail:"Agent Mail is degraded; use br state as the continuity anchor"} else empty end
    ]) as $pressure_reasons
  | (if ($resource_decision_bad or $resource_state_bad or $rch_saturated) then "wait"
     elif ($zero_ready or $proof_bad) then "split_file_blocker_bead"
     elif ($local_contention or $mail_degraded) then "run_cheap_local_non_cargo_checks"
     else "run_rch_proof" end) as $recommendation
  | {
      schema_version:$schema_version,
      bead_id:$bead_id,
      case_id:$case_id,
      source_revision:$source_revision,
      recommendation:$recommendation,
      pressure_level:(if $recommendation == "run_rch_proof" then "nominal"
        elif $recommendation == "run_cheap_local_non_cargo_checks" then "degraded"
        elif $recommendation == "split_file_blocker_bead" then "blocked"
        else "saturated" end),
      input_summary:{
        resource_envelope:{
          decision:resource_decision,
          memory_state:memory_state,
          disk_state:disk_state,
          rch_state:rch_resource_state
        },
        rch_jobs:{
          active_count:active_rch_count,
          max_active:max_rch_active,
          jobs:all_rch_jobs
        },
        local_processes:{
          cargo_count:cargo_count,
          rustc_count:rustc_count,
          active_compile_count:local_compile_count,
          max_local_compile_count:max_local_compile
        },
        proof_shards:{
          decision:proof_decision,
          stale:proof_stale,
          ready_count:(ready_shards | length),
          total_count:(proof_shards | length),
          shards:proof_shards
        },
        br_readiness:{
          ready_count:ready_count,
          open_count:open_count,
          ready_items:ready_items
        },
        agent_mail:{
          decision:mail_decision,
          status:mail_status,
          repair_allowed:false
        }
      },
      pressure_reasons:$pressure_reasons,
      recommended_commands:(
        if $recommendation == "wait" then [
          "wait for active RCH jobs to drain or choose source-only review work",
          "re-run this dashboard from fresh snapshots before admitting heavy proof work"
        ]
        elif $recommendation == "run_cheap_local_non_cargo_checks" then [
          "bash -n scripts/<changed-script>.sh scripts/e2e/<changed-smoke>.sh",
          "jq empty docs/<changed-contract>.json scripts/testdata/<changed-surface>/cases.json",
          "git diff --check -- <owned paths>"
        ]
        elif $recommendation == "split_file_blocker_bead" then [
          "br create --priority=2 --type bug \"Validation pressure blocker: missing ready proof shard or ready bead\"",
          "refresh br readiness and proof shard snapshots before retrying admission"
        ]
        else [
          "RCH_PRIORITY=low RCH_VISIBILITY=summary rch exec -- env RUSTUP_TOOLCHAIN=nightly CARGO_TARGET_DIR=/tmp/rch-target-franken-engine-validation-pressure CARGO_INCREMENTAL=0 RUSTFLAGS='\''-C linker=cc'\'' CARGO_BUILD_JOBS=1 cargo check --all-targets"
        ] end
      ),
      mutation_policy:{
        advisory_only:true,
        mutates_live_queues:false,
        mutates_br:false,
        sends_agent_mail:false,
        repairs_agent_mail_db:false,
        runs_cargo:false,
        runs_rch:false,
        queries_live_processes:false,
        queries_live_workers:false,
        deletes_or_overwrites_target_dirs:false
      },
      artifacts:{
        dashboard_json:$dashboard_path,
        dashboard_markdown:$report_path,
        commands:$commands_path,
        events:$events_path
      }
    }
  ' >"$dashboard_path"

jq -r '
  "# High-Core Validation Pressure Dashboard\n\n"
  + "- Recommendation: `" + .recommendation + "`\n"
  + "- Pressure: `" + .pressure_level + "`\n"
  + "- Ready beads: " + (.input_summary.br_readiness.ready_count | tostring) + "\n"
  + "- Active RCH jobs: " + (.input_summary.rch_jobs.active_count | tostring)
  + " / " + (.input_summary.rch_jobs.max_active | tostring) + "\n"
  + "- Local cargo/rustc: " + (.input_summary.local_processes.active_compile_count | tostring)
  + " / " + (.input_summary.local_processes.max_local_compile_count | tostring) + "\n"
  + "- Agent Mail: `" + .input_summary.agent_mail.decision + "` (`" + .input_summary.agent_mail.status + "`)\n\n"
  + "## Reasons\n\n"
  + (if (.pressure_reasons | length) == 0 then "- None\n" else (.pressure_reasons | map("- `" + .code + "`: " + .detail) | join("\n")) + "\n" end)
  + "\n## Recommended Commands\n\n"
  + (.recommended_commands | map("- " + .) | join("\n")) + "\n"
' "$dashboard_path" >"$report_path"

jq -nc --arg event "emitted" --arg case_id "$case_id" --arg artifact "$dashboard_path" \
  '{event:$event, case_id:$case_id, artifact:$artifact}' >>"$events_path"
