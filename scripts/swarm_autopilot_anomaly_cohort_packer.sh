#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_AUTOPILOT_ANOMALY_COHORT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-autopilot-anomaly-cohort}"
run_id="${SWARM_AUTOPILOT_ANOMALY_COHORT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AUTOPILOT_ANOMALY_COHORT_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

source_revision="${SWARM_AUTOPILOT_ANOMALY_COHORT_SOURCE_REVISION:-unknown}"
evidence_warehouse_json=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_autopilot_anomaly_cohort_packer.sh [OPTIONS]

Build replay-oriented anomaly cohorts from the autopilot evidence warehouse.
This script never mutates the warehouse, mutates beads, releases reservations,
sends Agent Mail, runs Cargo, runs RCH, mutates workers, or changes live queue
policy.

Required inputs:
  --evidence-warehouse-json FILE

Optional inputs:
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_autopilot_anomaly_cohorts.json
  swarm_autopilot_replay_index.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  cohort packaging is replayable; decision may be pass or degraded
  42 malformed or untrusted warehouse evidence prevented truthful cohort packaging
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --evidence-warehouse-json)
      evidence_warehouse_json="${2:-}"
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

if [[ -z "$evidence_warehouse_json" ]]; then
  printf 'evidence warehouse JSON is required\n' >&2
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for the anomaly cohort packer\n' >&2
  exit 2
fi

mkdir -p "$run_dir"
cohorts_path="${run_dir}/swarm_autopilot_anomaly_cohorts.json"
cohorts_tmp="${cohorts_path}.tmp"
replay_index_path="${run_dir}/swarm_autopilot_replay_index.json"
replay_index_tmp="${replay_index_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
warehouse_normalized="${run_dir}/evidence_warehouse.normalized.json"
fail_closed_reasons_jsonl="${run_dir}/fail_closed_reasons.jsonl"

printf './scripts/swarm_autopilot_anomaly_cohort_packer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$fail_closed_reasons_jsonl"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-autopilot-anomaly-cohort.event.v1" \
    --arg trace_id "trace-swarm-autopilot-anomaly-cohort-${run_id}" \
    --arg component "$1" \
    --arg event "$2" \
    --arg outcome "$3" \
    --arg error_code "$4" \
    --arg evidence_path "$5" \
    '{
      schema_version:$schema_version,
      trace_id:$trace_id,
      component:$component,
      event:$event,
      outcome:$outcome,
      error_code:(if $error_code == "" then null else $error_code end),
      evidence_path:$evidence_path
    }' >>"$events_path"
}

append_failure() {
  jq -nc \
    --arg code "$1" \
    --arg source_id "$2" \
    --arg detail "$3" \
    --arg remediation_command "$4" \
    '{
      code:$code,
      source_id:$source_id,
      detail:$detail,
      remediation_command:$remediation_command
    }' >>"$fail_closed_reasons_jsonl"
}

normalize_required_json() {
  local input_path="$1"
  local output_path="$2"
  local label="$3"
  if [[ ! -f "$input_path" ]]; then
    printf 'missing required %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  if ! jq empty "$input_path" >/dev/null 2>&1; then
    printf 'invalid required %s JSON: %s\n' "$label" "$input_path" >&2
    exit 64
  fi
  jq -cS . "$input_path" >"$output_path"
  write_event "$label" "input_loaded" "captured" "" "$output_path"
}

check_shape() {
  local path="$1"
  local expr="$2"
  local source_id="$3"
  local detail="$4"
  if ! jq -e "$expr" "$path" >/dev/null 2>&1; then
    append_failure "FE-SWARM-AUTOPILOT-COHORT-SCHEMA-DRIFT" "$source_id" "$detail" \
      "Refresh the warehouse bundle and restore the shipped schema before packaging cohorts."
  fi
}

normalize_required_json "$evidence_warehouse_json" "$warehouse_normalized" "evidence_warehouse"

check_shape "$warehouse_normalized" '
  type == "object"
  and .schema_version == "franken-engine.swarm-autopilot-evidence-warehouse.v1"
  and ((.artifact_rows // null) | type == "array")
  and ((.artifact_rows | length) > 0)
  and (((.hash_basis.warehouse_hash // "") | type) == "string")
  and ((.hash_basis.warehouse_hash // "") | length == 64)
  and (((.artifact_paths.evidence_warehouse_json // "") | type) == "string" and (.artifact_paths.evidence_warehouse_json | length > 0))
  and (((.artifact_paths.commands_txt // "") | type) == "string" and (.artifact_paths.commands_txt | length > 0))
  and (((.artifact_paths.events_jsonl // "") | type) == "string" and (.artifact_paths.events_jsonl | length > 0))
  and .mutation_policy.advisory_only == true
  and .mutation_policy.runs_cargo == false
  and .mutation_policy.runs_rch == false
' "evidence_warehouse_json" "warehouse snapshot lacks required schema, artifact rows, raw artifact paths, or safety markers"

if ! jq -e '
  .artifact_rows
  | all(.[]?;
      ((.source_id // "") | (type == "string" and length > 0))
      and ((.retention_class // "") | (type == "string" and length > 0))
      and ((.decision // "") | (type == "string" and length > 0))
      and ((.freshness // "") | (type == "string" and length > 0))
      and ((.sha256 // "") | (type == "string" and length > 0))
    )
' "$warehouse_normalized" >/dev/null 2>&1; then
  append_failure "FE-SWARM-AUTOPILOT-COHORT-SCHEMA-DRIFT" "artifact_rows" \
    "one or more warehouse rows are missing source_id, retention_class, decision, freshness, or sha256" \
    "Regenerate the warehouse rows with full source identifiers and fingerprints before packaging cohorts."
fi

for raw_ref in evidence_warehouse_json commands_txt events_jsonl; do
  if ! jq -e --arg raw_ref "$raw_ref" '.artifact_paths[$raw_ref] != null and (.artifact_paths[$raw_ref] | length > 0)' "$warehouse_normalized" >/dev/null; then
    append_failure "FE-SWARM-AUTOPILOT-COHORT-MISSING-RAW-REFERENCE" "$raw_ref" \
      "required raw artifact path ${raw_ref} is missing" \
      "Preserve commands, events, and evidence warehouse paths before building replay cohorts."
  fi
done

if jq -e '
  .decision == "fail_closed"
  and ([.fail_closed_reasons[]?.code?, .fail_closed_reasons[]?.detail?] | map(tostring) | any(test("local_fallback|contaminated"; "i")))
' "$warehouse_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-COHORT-CONTAMINATED" "evidence_warehouse_json" \
    "warehouse is contaminated by local fallback evidence" \
    "Discard contaminated local-fallback captures before treating anomaly cohorts as remote-only truth."
fi

if jq -e '
  ([.fail_closed_reasons[]?.code?] | any(test("STALE"; "i")))
  or (.artifact_rows | any(.freshness == "stale"))
' "$warehouse_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-COHORT-STALE-REFERENCE" "artifact_rows" \
    "warehouse contains stale reference evidence" \
    "Refresh stale warehouse captures before packaging replay cohorts."
fi

if [[ "$source_revision" == "unknown" ]]; then
  source_revision="$(jq -r '.source_revision // .run_identity.source_revision // "unknown"' "$warehouse_normalized")"
fi

if jq -e '
  def classify:
    if (.local_fallback_observed // .cohort_axes.local_fallback_observed // false) then
      "contaminated"
    elif ((.failure_mode // .cohort_axes.failure_mode // "") | test("locality|contradict|blocked"; "i")) then
      "blocked"
    elif (.decision != "pass" or .freshness != "fresh") then
      "degraded"
    else
      "reference"
    end;
  .artifact_rows
  | map(. + {
      cohort_group_id:(.cohort_group_id // .cohort_axes.cohort_group_id // .source_id),
      classification: classify
    })
  | group_by(.cohort_group_id)
  | any(([.[].classification] | unique | length) > 1)
' "$warehouse_normalized" >/dev/null; then
  append_failure "FE-SWARM-AUTOPILOT-COHORT-CONTRADICTORY-MEMBERSHIP" "artifact_rows" \
    "the same cohort_group_id resolves to multiple classifications" \
    "Split contradictory cohort_group_id values so each cohort is uniquely reference, degraded, blocked, or contaminated."
fi

decision="pass"
exit_code=0

if [[ -s "$fail_closed_reasons_jsonl" ]]; then
  decision="fail_closed"
  exit_code=42
elif jq -e '
  def classify:
    if (.local_fallback_observed // .cohort_axes.local_fallback_observed // false) then
      "contaminated"
    elif ((.failure_mode // .cohort_axes.failure_mode // "") | test("locality|contradict|blocked"; "i")) then
      "blocked"
    elif (.decision != "pass" or .freshness != "fresh") then
      "degraded"
    else
      "reference"
    end;
  .artifact_rows | any((classify) != "reference")
' "$warehouse_normalized" >/dev/null; then
  decision="degraded"
fi

allow_replay_on_fail_closed=true
if jq -e '[inputs] | length > 0' <"$fail_closed_reasons_jsonl" >/dev/null 2>&1; then
  if jq -e '[.code] | any(. == "FE-SWARM-AUTOPILOT-COHORT-MISSING-RAW-REFERENCE" or . == "FE-SWARM-AUTOPILOT-COHORT-STALE-REFERENCE")' "$fail_closed_reasons_jsonl" >/dev/null 2>&1; then
    allow_replay_on_fail_closed=false
  fi
fi

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-anomaly-cohorts.v1" \
  --arg bead_id "bd-gra1z.4" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg evidence_warehouse_json "$evidence_warehouse_json" \
  --arg cohorts_path "$cohorts_path" \
  --arg replay_index_path "$replay_index_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --slurpfile warehouse "$warehouse_normalized" \
  --slurpfile fail_closed_reasons "$fail_closed_reasons_jsonl" '
  def classify($row):
    if ($row.local_fallback_observed // $row.cohort_axes.local_fallback_observed // false) then
      "contaminated"
    elif (($row.failure_mode // $row.cohort_axes.failure_mode // "") | test("locality|contradict|blocked"; "i")) then
      "blocked"
    elif ($row.decision != "pass" or $row.freshness != "fresh") then
      "degraded"
    else
      "reference"
    end;
  def worker_id($row): ($row.worker_id // $row.cohort_axes.worker_id // "unknown-worker");
  def toolchain_target($row): ($row.toolchain_target // $row.cohort_axes.toolchain_target // "unknown-toolchain");
  def topology_class($row): ($row.topology_class // $row.cohort_axes.topology_class // "unknown-topology");
  def failure_mode($row):
    ($row.failure_mode // $row.cohort_axes.failure_mode //
      (if classify($row) == "reference" then "healthy_reference"
       elif classify($row) == "contaminated" then "local_fallback_contamination"
       elif classify($row) == "blocked" then "locality_contradiction"
       else "degraded_reference"
       end));
  def remediation($classification):
    if $classification == "reference" then
      ["Use this cohort as a healthy replay baseline."]
    elif $classification == "blocked" then
      ["Inspect locality contradiction evidence and refresh the upstream queue or locality artifacts before retrying."]
    elif $classification == "degraded" then
      ["Refresh degraded or non-pass evidence before promoting this cohort to a healthy reference."]
    else
      ["Discard contaminated local-fallback captures before treating this cohort as remote-only truth."]
    end;
  ($warehouse[0]) as $warehouse_doc
  | ($warehouse_doc.artifact_rows
      | map(. + {
          cohort_group_id:(.cohort_group_id // .cohort_axes.cohort_group_id // .source_id),
          classification: classify(.),
          worker_id: worker_id(.),
          toolchain_target: toolchain_target(.),
          topology_class: topology_class(.),
          normalized_failure_mode: failure_mode(.),
          local_fallback_marker:(.local_fallback_observed // .cohort_axes.local_fallback_observed // false)
        })
    ) as $rows
  | ($rows
      | group_by(.cohort_group_id)
      | map({
          cohort_id:.[0].cohort_group_id,
          classification:.[0].classification,
          worker_ids:(map(.worker_id) | unique | sort),
          toolchain_targets:(map(.toolchain_target) | unique | sort),
          topology_classes:(map(.topology_class) | unique | sort),
          failure_modes:(map(.normalized_failure_mode) | unique | sort),
          source_ids:(map(.source_id) | unique | sort),
          fingerprints:(map({source_id, sha256}) | unique_by(.source_id) | sort_by(.source_id)),
          raw_artifact_paths:{
            evidence_warehouse_json:$warehouse_doc.artifact_paths.evidence_warehouse_json,
            commands_txt:$warehouse_doc.artifact_paths.commands_txt,
            events_jsonl:$warehouse_doc.artifact_paths.events_jsonl
          },
          remote_truth_valid:(.[0].classification != "contaminated" and $decision != "fail_closed"),
          remediation_commands: remediation(.[0].classification)
        })
        | sort_by(.cohort_id)
    ) as $cohorts
  | {
      schema_version:$schema_version,
      bead_id:$bead_id,
      source_revision:$source_revision,
      warehouse_hash:$warehouse_doc.hash_basis.warehouse_hash,
      decision:$decision,
      cohort_summary:{
        total_cohort_count:($cohorts | length),
        reference_count:($cohorts | map(select(.classification == "reference")) | length),
        degraded_count:($cohorts | map(select(.classification == "degraded")) | length),
        blocked_count:($cohorts | map(select(.classification == "blocked")) | length),
        contaminated_count:($cohorts | map(select(.classification == "contaminated")) | length)
      },
      cohorts:$cohorts,
      fail_closed_reasons:($fail_closed_reasons | unique_by([.code, .source_id, .detail])),
      artifact_paths:{
        anomaly_cohorts_json:$cohorts_path,
        replay_index_json:$replay_index_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_path,
        evidence_warehouse_json:$evidence_warehouse_json
      },
      mutation_policy:{
        advisory_only:true,
        proof_only:true,
        fixture_fed_only:true,
        mutates_br:false,
        reassigns_beads:false,
        releases_reservations:false,
        sends_agent_mail:false,
        runs_cargo:false,
        runs_rch:false,
        mutates_remote_workers:false,
        changes_live_queue_policy:false
      }
    }' >"$cohorts_tmp"
mv "$cohorts_tmp" "$cohorts_path"

jq -n \
  --arg schema_version "franken-engine.swarm-autopilot-replay-index.v1" \
  --arg bead_id "bd-gra1z.4" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg cohorts_path "$cohorts_path" \
  --arg replay_index_path "$replay_index_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --arg evidence_warehouse_json "$evidence_warehouse_json" \
  --argjson allow_replay_on_fail_closed "$allow_replay_on_fail_closed" \
  --slurpfile cohorts_doc "$cohorts_path" '
  ($cohorts_doc[0]) as $doc
  | {
      schema_version:$schema_version,
      bead_id:$bead_id,
      source_revision:$source_revision,
      warehouse_hash:$doc.warehouse_hash,
      decision:$decision,
      entries:($doc.cohorts | map({
        cohort_id,
        classification,
        source_ids,
        replay_ready:(if $decision == "fail_closed" and $allow_replay_on_fail_closed == false then false else true end),
        remote_truth_valid:.remote_truth_valid,
        evidence_refs:.raw_artifact_paths,
        remediation_commands:.remediation_commands
      })),
      artifact_paths:{
        replay_index_json:$replay_index_path,
        anomaly_cohorts_json:$cohorts_path,
        events_jsonl:$events_path,
        commands_txt:$commands_path,
        report_md:$report_path,
        evidence_warehouse_json:$evidence_warehouse_json
      }
    }' >"$replay_index_tmp"
mv "$replay_index_tmp" "$replay_index_path"

{
  printf '# SWARM_AUTOPILOT_ANOMALY_COHORT_PACKER\n\n'
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- warehouse_hash: \`%s\`\n" "$(jq -r '.warehouse_hash' "$cohorts_path")"
  printf -- "- total_cohort_count: \`%s\`\n" "$(jq -r '.cohort_summary.total_cohort_count' "$cohorts_path")"
  printf '\n## Cohorts\n'
  jq -r '.cohorts[] | "- `\(.cohort_id)` class=`\(.classification)` sources=`\(.source_ids | length)`"' "$cohorts_path"
  if jq -e '.fail_closed_reasons | length > 0' "$cohorts_path" >/dev/null; then
    printf '\n## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `\(.code)` from `\(.source_id)`: \(.detail)"' "$cohorts_path"
  fi
} >"$report_path"

write_event "anomaly_cohort_packer" "cohorts_emitted" "$decision" "" "$cohorts_path"
write_event "anomaly_cohort_packer" "replay_index_emitted" "$decision" "" "$replay_index_path"

exit "$exit_code"
