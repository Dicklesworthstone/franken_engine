#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_EXECUTION_QUEUE_HINDSIGHT_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-execution-queue-hindsight}"
run_id="${SWARM_EXECUTION_QUEUE_HINDSIGHT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_EXECUTION_QUEUE_HINDSIGHT_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

queue_artifact_json=""
queue_run_manifest_json=""
normalized_queue_input_json=""
risk_budget_receipt_json=""
bottleneck_report_json=""
bead_status_snapshot_json=""
bead_timing_snapshot_json=""
owner_contact_snapshot_json=""
reservation_friction_snapshot_json=""
proof_outcome_snapshot_json=""
checkpoint_restore_state_json=""
source_revision=""
observation_epoch_seconds=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_execution_queue_hindsight_normalizer.sh \
  --queue-artifact-json FILE \
  --queue-run-manifest-json FILE \
  --normalized-queue-input-json FILE \
  --risk-budget-receipt-json FILE \
  --bottleneck-report-json FILE \
  --bead-status-snapshot-json FILE \
  --bead-timing-snapshot-json FILE \
  --owner-contact-snapshot-json FILE \
  --reservation-friction-snapshot-json FILE \
  --proof-outcome-snapshot-json FILE \
  --checkpoint-restore-state-json FILE \
  [OPTIONS]

Joins SWARM-CTRL-XII queue advice with later aftermath evidence into the
SWARM-CTRL-XIII hindsight input/report contract. This script is advisory-only:
it does not update beads, reassign owners, release reservations, send Agent
Mail, run cargo, mutate worker state, or change the active queue.

Required:
  --queue-artifact-json FILE
  --queue-run-manifest-json FILE
  --normalized-queue-input-json FILE
  --risk-budget-receipt-json FILE
  --bottleneck-report-json FILE
  --bead-status-snapshot-json FILE
  --bead-timing-snapshot-json FILE
  --owner-contact-snapshot-json FILE
  --reservation-friction-snapshot-json FILE
  --proof-outcome-snapshot-json FILE
  --checkpoint-restore-state-json FILE

Optional:
  --source-revision REV
  --observation-epoch-seconds N
  --output-dir DIR

Artifacts:
  hindsight_input.json
  hindsight_report.json
  evidence_ledger.json
  counterfactual_candidates.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  hindsight report is replayable; decision may be pass or degraded
  42 fail-closed due to malformed evidence, timestamp contradictions, unknown
     tasks, duplicate IDs, missing first actions, inconsistent ownership, or
     local-rch fallback being promoted as healthy proof
  64 usage or missing tool/file errors
EOF
}

is_int() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --queue-artifact-json)
      queue_artifact_json="${2:-}"
      shift 2
      ;;
    --queue-run-manifest-json)
      queue_run_manifest_json="${2:-}"
      shift 2
      ;;
    --normalized-queue-input-json)
      normalized_queue_input_json="${2:-}"
      shift 2
      ;;
    --risk-budget-receipt-json)
      risk_budget_receipt_json="${2:-}"
      shift 2
      ;;
    --bottleneck-report-json)
      bottleneck_report_json="${2:-}"
      shift 2
      ;;
    --bead-status-snapshot-json)
      bead_status_snapshot_json="${2:-}"
      shift 2
      ;;
    --bead-timing-snapshot-json)
      bead_timing_snapshot_json="${2:-}"
      shift 2
      ;;
    --owner-contact-snapshot-json)
      owner_contact_snapshot_json="${2:-}"
      shift 2
      ;;
    --reservation-friction-snapshot-json)
      reservation_friction_snapshot_json="${2:-}"
      shift 2
      ;;
    --proof-outcome-snapshot-json)
      proof_outcome_snapshot_json="${2:-}"
      shift 2
      ;;
    --checkpoint-restore-state-json)
      checkpoint_restore_state_json="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision="${2:-}"
      shift 2
      ;;
    --observation-epoch-seconds)
      observation_epoch_seconds="${2:-}"
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

required_paths=(
  "$queue_artifact_json"
  "$queue_run_manifest_json"
  "$normalized_queue_input_json"
  "$risk_budget_receipt_json"
  "$bottleneck_report_json"
  "$bead_status_snapshot_json"
  "$bead_timing_snapshot_json"
  "$owner_contact_snapshot_json"
  "$reservation_friction_snapshot_json"
  "$proof_outcome_snapshot_json"
  "$checkpoint_restore_state_json"
)
for path in "${required_paths[@]}"; do
  if [[ -z "$path" ]]; then
    printf 'all required hindsight JSON inputs must be provided\n' >&2
    usage
    exit 64
  fi
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm execution queue hindsight normalization\n' >&2
  exit 64
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm execution queue hindsight normalization\n' >&2
  exit 64
fi
if [[ -n "$observation_epoch_seconds" ]] && ! is_int "$observation_epoch_seconds"; then
  printf 'observation epoch seconds must be a non-negative integer\n' >&2
  exit 64
fi

if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
hindsight_input_path="${run_dir}/hindsight_input.json"
hindsight_report_path="${run_dir}/hindsight_report.json"
evidence_ledger_path="${run_dir}/evidence_ledger.json"
counterfactual_candidates_path="${run_dir}/counterfactual_candidates.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
bundle_path="${run_dir}/hindsight_bundle.core.json"

queue_artifact_normalized="${run_dir}/queue_artifact.normalized.json"
queue_run_manifest_normalized="${run_dir}/queue_run_manifest.normalized.json"
normalized_queue_input_normalized="${run_dir}/normalized_queue_input.normalized.json"
risk_budget_receipt_normalized="${run_dir}/risk_budget_receipt.normalized.json"
bottleneck_report_normalized="${run_dir}/bottleneck_report.normalized.json"
bead_status_normalized="${run_dir}/bead_status_snapshot.normalized.json"
bead_timing_normalized="${run_dir}/bead_timing_snapshot.normalized.json"
owner_contact_normalized="${run_dir}/owner_contact_snapshot.normalized.json"
reservation_friction_normalized="${run_dir}/reservation_friction_snapshot.normalized.json"
proof_outcome_normalized="${run_dir}/proof_outcome_snapshot.normalized.json"
checkpoint_restore_normalized="${run_dir}/checkpoint_restore_state.normalized.json"

printf './scripts/swarm_execution_queue_hindsight_normalizer.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"

write_event() {
  jq -nc \
    --arg schema_version "franken-engine.swarm-execution-queue-hindsight.event.v1" \
    --arg event_name "$1" \
    --arg detail "$2" \
    --arg source_revision "$source_revision" \
    '{schema_version:$schema_version,event_name:$event_name,detail:$detail,source_revision:$source_revision}' >>"$events_path"
}

json_input() {
  local path="$1"
  local output_path="$2"
  local label="$3"

  if [[ ! -f "$path" ]]; then
    printf 'required hindsight input not found: %s\n' "$path" >&2
    exit 64
  fi
  if ! jq empty "$path" >/dev/null 2>&1; then
    printf 'required hindsight input is not valid JSON: %s\n' "$path" >&2
    exit 64
  fi
  jq -cS . "$path" >"$output_path"
  write_event "input.loaded" "$label"
}

json_input "$queue_artifact_json" "$queue_artifact_normalized" "queue_artifact_json"
json_input "$queue_run_manifest_json" "$queue_run_manifest_normalized" "queue_run_manifest_json"
json_input "$normalized_queue_input_json" "$normalized_queue_input_normalized" "normalized_queue_input_json"
json_input "$risk_budget_receipt_json" "$risk_budget_receipt_normalized" "risk_budget_receipt_json"
json_input "$bottleneck_report_json" "$bottleneck_report_normalized" "bottleneck_report_json"
json_input "$bead_status_snapshot_json" "$bead_status_normalized" "bead_status_snapshot_json"
json_input "$bead_timing_snapshot_json" "$bead_timing_normalized" "bead_timing_snapshot_json"
json_input "$owner_contact_snapshot_json" "$owner_contact_normalized" "owner_contact_snapshot_json"
json_input "$reservation_friction_snapshot_json" "$reservation_friction_normalized" "reservation_friction_snapshot_json"
json_input "$proof_outcome_snapshot_json" "$proof_outcome_normalized" "proof_outcome_snapshot_json"
json_input "$checkpoint_restore_state_json" "$checkpoint_restore_normalized" "checkpoint_restore_state_json"

jq -n \
  --arg source_revision "$source_revision" \
  --arg observation_epoch_seconds "$observation_epoch_seconds" \
  --arg hindsight_input_path "$hindsight_input_path" \
  --arg hindsight_report_path "$hindsight_report_path" \
  --arg evidence_ledger_path "$evidence_ledger_path" \
  --arg counterfactual_candidates_path "$counterfactual_candidates_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" \
  --slurpfile queue_artifact "$queue_artifact_normalized" \
  --slurpfile run_manifest "$queue_run_manifest_normalized" \
  --slurpfile normalized_input "$normalized_queue_input_normalized" \
  --slurpfile risk_budget "$risk_budget_receipt_normalized" \
  --slurpfile bottleneck_report "$bottleneck_report_normalized" \
  --slurpfile bead_status "$bead_status_normalized" \
  --slurpfile bead_timing "$bead_timing_normalized" \
  --slurpfile owner_contact "$owner_contact_normalized" \
  --slurpfile reservation_friction "$reservation_friction_normalized" \
  --slurpfile proof_outcome "$proof_outcome_normalized" \
  --slurpfile checkpoint_restore "$checkpoint_restore_normalized" '
    def hex64:
      type == "string" and test("^[0-9a-f]{64}$");

    def int_or_null:
      if type == "number" then .
      elif type == "string" and test("^[0-9]+$") then tonumber
      else null
      end;

    def id_of:
      if type == "object" then
        (.task_id // .bead_id // .id // "")
      else
        ""
      end | tostring;

    def rows($doc; $primary; $secondary):
      if (($doc[$primary] // null) | type) == "array" then
        $doc[$primary]
      elif (($doc[$secondary] // null) | type) == "array" then
        $doc[$secondary]
      else
        []
      end;

    def queue_rows($doc):
      if (($doc.queue // null) | type) == "array" then
        $doc.queue
      elif (($doc.queue_artifact.queue // null) | type) == "array" then
        $doc.queue_artifact.queue
      elif (($doc.runner.queue // null) | type) == "array" then
        $doc.runner.queue
      else
        []
      end;

    def normalized_tasks($doc):
      if (($doc.tasks // null) | type) == "array" then $doc.tasks else [] end;

    def first_by_id($rows; $id):
      [$rows[]? | select(id_of == $id)][0] // {};

    def rows_by_id($rows; $id):
      [$rows[]? | select(id_of == $id)];

    def duplicates($rows):
      [$rows[]? | id_of | select(length > 0)]
      | sort
      | group_by(.)
      | map(select(length > 1) | .[0]);

    def metadata_failures($source_id; $doc):
      [
        if (($doc.schema_version // "") | tostring | length) == 0 then
          {kind:"missing_input_metadata",source:$source_id,label:"schema_version",detail:"required input lacks schema_version"}
        else empty end,
        if (($doc.captured_epoch_seconds // null) | int_or_null) == null then
          {kind:"missing_input_metadata",source:$source_id,label:"captured_epoch_seconds",detail:"required input lacks captured_epoch_seconds"}
        else empty end,
        if (($doc.source_revision // "") | tostring | length) == 0 then
          {kind:"missing_input_metadata",source:$source_id,label:"source_revision",detail:"required input lacks source_revision"}
        else empty end,
        if (($doc.artifact_path // "") | tostring | length) == 0 then
          {kind:"missing_input_metadata",source:$source_id,label:"artifact_path",detail:"required input lacks artifact_path"}
        else empty end,
        if (($doc.content_hash_hex // "") | hex64 | not) then
          {kind:"missing_input_metadata",source:$source_id,label:"content_hash_hex",detail:"required input lacks a hex sha256 content hash"}
        else empty end,
        if (($doc.trust_state // "primary") == "rejected") then
          {kind:"rejected_required_evidence",source:$source_id,label:"trust_state",detail:"required evidence is rejected"}
        else empty end,
        if (($doc.freshness_state // "fresh") != "fresh") then
          {kind:"stale_required_evidence",source:$source_id,label:"freshness_state",detail:"required evidence is not fresh"}
        else empty end
      ];

    def evidence_row($source_id; $doc):
      {
        artifact_id: ($doc.artifact_id // $source_id),
        source_id: $source_id,
        schema_version: ($doc.schema_version // "unknown"),
        path: ($doc.artifact_path // "unknown"),
        content_hash_hex: ($doc.content_hash_hex // ""),
        source_revision: ($doc.source_revision // "unknown"),
        captured_epoch_seconds: (($doc.captured_epoch_seconds // 0) | int_or_null),
        trust_state: ($doc.trust_state // "primary"),
        freshness_state: ($doc.freshness_state // "fresh"),
        required: true
      };

    def owner_value($row):
      (($row.owner // $row.assignee // $row.agent_name // "") | tostring);

    def proof_value($row):
      (($row.proof_outcome // $row.state // "unknown") | tostring);

    def reservation_holders($rows; $id):
      [rows_by_id($rows; $id)[]? | (.holder // .reservation_holder // .agent_name // empty) | tostring | select(length > 0)]
      | unique
      | sort;

    def proof_is_local_fallback_healthy($row):
      (($row.local_fallback_detected // false) == true)
      and (proof_value($row) | test("healthy|success|complete|completed|passed|remote_only_ok"));

    def drift_class($actual; $owner_inconsistent; $holders; $proof; $restore; $rank_delta; $start_delta):
      if ($restore | test("blocked|manual|review")) then "restore_drift"
      elif ($proof | test("brownout|degraded|failed|unavailable|local")) then "proof_drift"
      elif $owner_inconsistent then "ownership_drift"
      elif ($holders | length) > 1 then "reservation_drift"
      elif (($rank_delta // 0) != 0) then "ranking_drift"
      elif (($start_delta // 0) > 3600) then "timing_drift"
      elif $actual == "not_observed" then "data_gap"
      else "none"
      end;

    def fidelity_class($actual; $proof; $restore; $start_delta):
      if ($proof | test("local")) then "unsafe_to_score"
      elif ($restore | test("blocked|manual|review")) then "justified_override"
      elif $actual == "not_observed" then "insufficient_evidence"
      elif ($actual == "deferred" or $actual == "blocked") then "justified_override"
      elif (($start_delta // 0) > 3600) then "delayed_match"
      elif ($actual == "started" or $actual == "closed" or $actual == "preexisting_work") then "matched"
      else "stale_advice"
      end;

    def confidence_band($fidelity; $drift):
      if $fidelity == "insufficient_evidence" or $drift == "data_gap" then "insufficient_evidence"
      elif $fidelity == "unsafe_to_score" or $drift == "proof_drift" then "low"
      elif $fidelity == "delayed_match" or $fidelity == "justified_override" or $drift != "none" then "medium"
      else "high"
      end;

    ($queue_artifact[0]) as $queue_doc
    | ($run_manifest[0]) as $manifest_doc
    | ($normalized_input[0]) as $input_doc
    | ($risk_budget[0]) as $risk_doc
    | ($bottleneck_report[0]) as $bottleneck_doc
    | ($bead_status[0]) as $status_doc
    | ($bead_timing[0]) as $timing_doc
    | ($owner_contact[0]) as $owner_doc
    | ($reservation_friction[0]) as $reservation_doc
    | ($proof_outcome[0]) as $proof_doc
    | ($checkpoint_restore[0]) as $restore_doc
    | [
        evidence_row("queue_artifact_json"; $queue_doc),
        evidence_row("queue_run_manifest_json"; $manifest_doc),
        evidence_row("normalized_queue_input_json"; $input_doc),
        evidence_row("risk_budget_receipt_json"; $risk_doc),
        evidence_row("bottleneck_report_json"; $bottleneck_doc),
        evidence_row("bead_status_snapshot_json"; $status_doc),
        evidence_row("bead_timing_snapshot_json"; $timing_doc),
        evidence_row("owner_contact_snapshot_json"; $owner_doc),
        evidence_row("reservation_friction_snapshot_json"; $reservation_doc),
        evidence_row("proof_outcome_snapshot_json"; $proof_doc),
        evidence_row("checkpoint_restore_state_json"; $restore_doc)
      ] as $ledger_rows
    | (
        metadata_failures("queue_artifact_json"; $queue_doc)
        + metadata_failures("queue_run_manifest_json"; $manifest_doc)
        + metadata_failures("normalized_queue_input_json"; $input_doc)
        + metadata_failures("risk_budget_receipt_json"; $risk_doc)
        + metadata_failures("bottleneck_report_json"; $bottleneck_doc)
        + metadata_failures("bead_status_snapshot_json"; $status_doc)
        + metadata_failures("bead_timing_snapshot_json"; $timing_doc)
        + metadata_failures("owner_contact_snapshot_json"; $owner_doc)
        + metadata_failures("reservation_friction_snapshot_json"; $reservation_doc)
        + metadata_failures("proof_outcome_snapshot_json"; $proof_doc)
        + metadata_failures("checkpoint_restore_state_json"; $restore_doc)
      ) as $metadata_failures
    | (queue_rows($queue_doc)) as $queue_rows
    | (normalized_tasks($input_doc)) as $input_tasks
    | (rows($status_doc; "tasks"; "beads")) as $status_rows
    | (rows($timing_doc; "tasks"; "timings")) as $timing_rows
    | (rows($owner_doc; "contacts"; "owners")) as $owner_rows
    | (rows($reservation_doc; "reservations"; "friction")) as $reservation_rows
    | (rows($proof_doc; "proofs"; "tasks")) as $proof_rows
    | (rows($restore_doc; "restores"; "tasks")) as $restore_rows
    | ([$queue_rows[]? | id_of | select(length > 0)] | unique | sort) as $queue_ids
    | (
        if ($observation_epoch_seconds | length) > 0 then ($observation_epoch_seconds | int_or_null)
        else (
          $status_doc.observation_epoch_seconds
          // $timing_doc.observation_epoch_seconds
          // $owner_doc.observation_epoch_seconds
          // $reservation_doc.observation_epoch_seconds
          // $proof_doc.observation_epoch_seconds
          // $restore_doc.observation_epoch_seconds
          // null
        )
        end
      ) as $observation_epoch
    | (
        $queue_doc.queue_issued_epoch_seconds
        // $manifest_doc.queue_issued_epoch_seconds
        // $input_doc.queue_issued_epoch_seconds
        // $input_doc.generated_epoch_seconds
        // null
      ) as $queue_issued_epoch
    | ($queue_rows | to_entries | map(
        .key as $idx
        | .value as $queue_row
        | (id_of | .) as $ignored
        | ($queue_row | id_of) as $task_id
        | first_by_id($input_tasks; $task_id) as $input_task
        | first_by_id($status_rows; $task_id) as $status_row
        | first_by_id($timing_rows; $task_id) as $timing_row
        | first_by_id($owner_rows; $task_id) as $owner_row
        | first_by_id($proof_rows; $task_id) as $proof_row
        | first_by_id($restore_rows; $task_id) as $restore_row
        | reservation_holders($reservation_rows; $task_id) as $holders
        | (($queue_row.rank // ($idx + 1)) | int_or_null) as $recommended_rank
        | (($timing_row.actual_rank // null) | int_or_null) as $actual_rank
        | (($timing_row.actual_started_epoch_seconds // $status_row.actual_started_epoch_seconds // null) | int_or_null) as $actual_started
        | (($timing_row.actual_closed_epoch_seconds // $status_row.actual_closed_epoch_seconds // null) | int_or_null) as $actual_closed
        | (
            $status_row.actual_outcome
            // $timing_row.actual_outcome
            // (if (($status_row.status // "") == "closed") then "closed"
                elif (($status_row.status // "") == "in_progress") and ($actual_started != null) then "started"
                elif (($status_row.status // "") == "blocked") then "blocked"
                elif (($status_row.status // "") == "deferred") then "deferred"
                else "not_observed"
                end)
          ) as $actual_outcome
        | (owner_value($status_row)) as $status_owner
        | (owner_value($input_task)) as $input_owner
        | (owner_value($owner_row)) as $contact_owner
        | ((($status_owner | length) > 0 and ($contact_owner | length) > 0 and $status_owner != $contact_owner)
            or (($input_owner | length) > 0 and ($contact_owner | length) > 0 and $input_owner != $contact_owner)) as $owner_inconsistent
        | (proof_value($proof_row)) as $proof_state
        | (($restore_row.checkpoint_restore_outcome // $restore_row.state // "none") | tostring) as $restore_state
        | (if $recommended_rank != null and $actual_rank != null then ($actual_rank - $recommended_rank) else null end) as $rank_delta
        | (if $queue_issued_epoch != null and $actual_started != null then ($actual_started - $queue_issued_epoch) else null end) as $start_delta
        | (if $queue_issued_epoch != null and $actual_closed != null then ($actual_closed - $queue_issued_epoch) else null end) as $close_delta
        | drift_class($actual_outcome; $owner_inconsistent; $holders; $proof_state; $restore_state; $rank_delta; $start_delta) as $drift
        | fidelity_class($actual_outcome; $proof_state; $restore_state; $start_delta) as $fidelity
        | confidence_band($fidelity; $drift) as $confidence
        | {
            task_id: $task_id,
            recommended_rank: $recommended_rank,
            recommended_wave: (($queue_row.wave // "unknown") | tostring),
            recommended_first_action: (($queue_row.first_action // $input_task.first_action // "") | tostring),
            actual_outcome: ($actual_outcome | tostring),
            actual_start_delta_seconds: $start_delta,
            actual_close_delta_seconds: $close_delta,
            rank_delta: $rank_delta,
            defer_reason: (($status_row.defer_reason // $timing_row.defer_reason // "none") | tostring),
            override_reason: (($status_row.override_reason // $proof_row.override_reason // $restore_row.override_reason // "none") | tostring),
            owner_friction_outcome: (($owner_row.owner_friction_outcome // $owner_row.outcome // (if $owner_inconsistent then "inconsistent_owner" else "none" end)) | tostring),
            reservation_friction_outcome: ((rows_by_id($reservation_rows; $task_id)[0].reservation_friction_outcome // rows_by_id($reservation_rows; $task_id)[0].outcome // (if ($holders | length) > 0 then "reservation_observed" else "none" end)) | tostring),
            proof_outcome: $proof_state,
            checkpoint_restore_outcome: $restore_state,
            fidelity_class: $fidelity,
            drift_class: $drift,
            confidence_band: $confidence,
            counterfactual_candidate: ($confidence != "high" or $drift != "none"),
            owner_identity: {
              queued_assignee: $input_owner,
              status_assignee: $status_owner,
              contact_owner: $contact_owner,
              inconsistent: $owner_inconsistent
            },
            reservation_holders: $holders
          }
      )) as $hindsight_rows
    | (
        $metadata_failures
        + (if ($queue_rows | length) == 0 then [{kind:"empty_queue_artifact",source:"queue_artifact_json",label:"queue",detail:"queue artifact contains no queue rows"}] else [] end)
        + (if $queue_issued_epoch == null then [{kind:"missing_required_timestamp",source:"queue_artifact_json",label:"queue_issued_epoch_seconds",detail:"queue issue timestamp is missing"}] else [] end)
        + (if $observation_epoch == null then [{kind:"missing_required_timestamp",source:"aftermath",label:"observation_epoch_seconds",detail:"observation timestamp is missing"}] else [] end)
        + (if ($queue_issued_epoch != null and $observation_epoch != null and $observation_epoch < $queue_issued_epoch) then [{kind:"contradictory_timestamp",source:"aftermath",label:"observation_epoch_seconds",detail:"observation timestamp predates queue issue"}] else [] end)
        + (duplicates($queue_rows) | map({kind:"duplicate_task_id",source:"queue_artifact_json",label:.,detail:"queue artifact repeats task_id"}))
        + (duplicates($status_rows) | map({kind:"duplicate_task_id",source:"bead_status_snapshot_json",label:.,detail:"status snapshot repeats task_id"}))
        + (duplicates($timing_rows) | map({kind:"duplicate_task_id",source:"bead_timing_snapshot_json",label:.,detail:"timing snapshot repeats task_id"}))
        + (duplicates($owner_rows) | map({kind:"duplicate_task_id",source:"owner_contact_snapshot_json",label:.,detail:"owner snapshot repeats task_id"}))
        + (duplicates($proof_rows) | map({kind:"duplicate_task_id",source:"proof_outcome_snapshot_json",label:.,detail:"proof snapshot repeats task_id"}))
        + (duplicates($restore_rows) | map({kind:"duplicate_task_id",source:"checkpoint_restore_state_json",label:.,detail:"restore snapshot repeats task_id"}))
        + ([$queue_rows[]? | select(((.first_action // "") | tostring | length) == 0) | {kind:"missing_first_action",source:"queue_artifact_json",label:(id_of),detail:"queue row lacks first_action"}])
        + ([$status_rows[], $timing_rows[], $owner_rows[], $reservation_rows[], $proof_rows[], $restore_rows[] | id_of | select(length > 0) | select(($queue_ids | index(.)) == null) | {kind:"unknown_task_reference",source:"aftermath",label:.,detail:"aftermath snapshot references a task absent from the queue artifact"}] | unique_by(.kind + .label))
        + ([$hindsight_rows[]? | select(.owner_identity.inconsistent == true) | {kind:"inconsistent_owner_identity",source:"owner_contact_snapshot_json",label:.task_id,detail:"status/input owner disagrees with owner-contact evidence"}])
        + ([$hindsight_rows[]? | select((.reservation_holders | length) > 1) | {kind:"inconsistent_reservation_holder",source:"reservation_friction_snapshot_json",label:.task_id,detail:"reservation evidence has multiple holders for one task"}])
        + ([$proof_rows[]? | select(proof_is_local_fallback_healthy(.)) | {kind:"local_rch_fallback_promoted",source:"proof_outcome_snapshot_json",label:(id_of),detail:"local-rch fallback cannot be treated as healthy proof completion"}])
        + ([$hindsight_rows[]? | select(.actual_start_delta_seconds != null and .actual_start_delta_seconds < 0 and .actual_outcome != "preexisting_work") | {kind:"contradictory_timestamp",source:"bead_timing_snapshot_json",label:.task_id,detail:"actual start predates queue issue without preexisting_work"}])
        + ([$hindsight_rows[]? | select(.actual_close_delta_seconds != null and .actual_start_delta_seconds != null and .actual_close_delta_seconds < .actual_start_delta_seconds) | {kind:"contradictory_timestamp",source:"bead_timing_snapshot_json",label:.task_id,detail:"actual close predates actual start"}])
      ) as $fail_closed_reasons
    | (
        ([$hindsight_rows[]? | select(.actual_outcome == "not_observed") | {kind:"missing_outcome",source:"bead_status_snapshot_json",label:.task_id,detail:"no actual outcome was observed for queued task"}])
        + ([$hindsight_rows[]? | select(.owner_friction_outcome | test("stale|contact|friction")) | {kind:"owner_friction",source:"owner_contact_snapshot_json",label:.task_id,detail:.owner_friction_outcome}])
        + ([$hindsight_rows[]? | select(.reservation_friction_outcome | test("contend|conflict|blocked")) | {kind:"reservation_friction",source:"reservation_friction_snapshot_json",label:.task_id,detail:.reservation_friction_outcome}])
        + ([$hindsight_rows[]? | select(.proof_outcome | test("brownout|degraded|failed|unavailable")) | {kind:"proof_brownout",source:"proof_outcome_snapshot_json",label:.task_id,detail:.proof_outcome}])
        + ([$hindsight_rows[]? | select(.checkpoint_restore_outcome | test("blocked|manual|review")) | {kind:"checkpoint_restore_attention",source:"checkpoint_restore_state_json",label:.task_id,detail:.checkpoint_restore_outcome}])
      ) as $degraded_inputs
    | (if ($fail_closed_reasons | length) > 0 then "fail_closed"
       elif ($degraded_inputs | length) > 0 then "degraded"
       else "pass"
       end) as $decision
    | ([$hindsight_rows[]? | select(.counterfactual_candidate == true) | {
        candidate_id: ("hindsight-" + .task_id + "-" + .drift_class),
        task_id: .task_id,
        reason: (.drift_class + "/" + .fidelity_class),
        proposed_weight_delta: (if .drift_class == "proof_drift" then "increase proof brownout penalty"
          elif .drift_class == "ownership_drift" then "increase owner-friction penalty"
          elif .drift_class == "reservation_drift" then "increase reservation-contention penalty"
          elif .drift_class == "data_gap" then "require stronger aftermath evidence"
          else "replay ranking weights"
          end),
        expected_fidelity_gain_millionths: (if .confidence_band == "insufficient_evidence" then 120000 else 240000 end),
        risk: (if .fidelity_class == "unsafe_to_score" then "high" elif .confidence_band == "low" then "medium" else "low" end),
        required_replay_inputs: [
          "hindsight_input.json",
          "hindsight_report.json",
          "execution_queue_artifact.json",
          "counterfactual_candidates.json"
        ]
      }]) as $candidates
    | {
        hindsight_input: {
          schema_version: "franken-engine.swarm-execution-queue-hindsight-input.v1",
          normalizer_schema_version: "franken-engine.swarm-execution-queue-hindsight-normalizer.v1",
          source_revision: $source_revision,
          queue_issued_epoch_seconds: $queue_issued_epoch,
          observation_epoch_seconds: $observation_epoch,
          queue_task_ids: $queue_ids,
          source_artifacts: $ledger_rows,
          queue_rows: $queue_rows,
          normalized_queue_tasks: $input_tasks,
          aftermath_snapshots: {
            bead_status_rows: $status_rows,
            bead_timing_rows: $timing_rows,
            owner_contact_rows: $owner_rows,
            reservation_friction_rows: $reservation_rows,
            proof_outcome_rows: $proof_rows,
            checkpoint_restore_rows: $restore_rows
          },
          artifact_paths: {
            hindsight_input_json: $hindsight_input_path,
            hindsight_report_json: $hindsight_report_path,
            evidence_ledger_json: $evidence_ledger_path,
            counterfactual_candidates_json: $counterfactual_candidates_path,
            events_jsonl: $events_path,
            commands_txt: $commands_path,
            report_md: $report_path
          }
        },
        evidence_ledger: {
          schema_version: "franken-engine.swarm-execution-queue-hindsight-evidence-ledger.v1",
          source_revision: $source_revision,
          rows: $ledger_rows,
          required_count: ($ledger_rows | length),
          rejected_count: ([$ledger_rows[]? | select(.trust_state == "rejected")] | length),
          stale_count: ([$ledger_rows[]? | select(.freshness_state != "fresh")] | length)
        },
        hindsight_report: {
          schema_version: "franken-engine.swarm-execution-queue-hindsight-report.v1",
          source_revision: $source_revision,
          decision: $decision,
          queue_issued_epoch_seconds: $queue_issued_epoch,
          observation_epoch_seconds: $observation_epoch,
          summary: {
            queue_task_count: ($hindsight_rows | length),
            matched_count: ([$hindsight_rows[]? | select(.fidelity_class == "matched")] | length),
            delayed_match_count: ([$hindsight_rows[]? | select(.fidelity_class == "delayed_match")] | length),
            justified_override_count: ([$hindsight_rows[]? | select(.fidelity_class == "justified_override")] | length),
            unsafe_to_score_count: ([$hindsight_rows[]? | select(.fidelity_class == "unsafe_to_score")] | length),
            insufficient_evidence_count: ([$hindsight_rows[]? | select(.fidelity_class == "insufficient_evidence")] | length),
            counterfactual_candidate_count: ($candidates | length),
            fail_closed_reason_count: ($fail_closed_reasons | length),
            degraded_input_count: ($degraded_inputs | length)
          },
          fail_closed_reasons: $fail_closed_reasons,
          degraded_inputs: $degraded_inputs,
          rows: $hindsight_rows,
          artifact_paths: {
            hindsight_input_json: $hindsight_input_path,
            hindsight_report_json: $hindsight_report_path,
            evidence_ledger_json: $evidence_ledger_path,
            counterfactual_candidates_json: $counterfactual_candidates_path,
            events_jsonl: $events_path,
            commands_txt: $commands_path,
            report_md: $report_path
          }
        },
        counterfactual_candidates: {
          schema_version: "franken-engine.swarm-execution-queue-counterfactual-candidates.v1",
          source_revision: $source_revision,
          candidates: $candidates
        }
      }
  ' >"$bundle_path"

jq '.hindsight_input' "$bundle_path" >"$hindsight_input_path"
jq '.evidence_ledger' "$bundle_path" >"$evidence_ledger_path"
jq '.hindsight_report' "$bundle_path" >"$hindsight_report_path"
jq '.counterfactual_candidates' "$bundle_path" >"$counterfactual_candidates_path"

hindsight_id="swarm-execution-queue-hindsight-$(jq -cS 'del(.artifact_paths)' "$hindsight_report_path" | sha256sum | awk '{print $1}' | cut -c1-16)"
tmp_report="${hindsight_report_path}.tmp"
jq --arg hindsight_id "$hindsight_id" '. + {hindsight_id:$hindsight_id}' "$hindsight_report_path" >"$tmp_report"
mv "$tmp_report" "$hindsight_report_path"

write_event "hindsight_report.written" "$(jq -r '.decision + " / rows=" + (.summary.queue_task_count | tostring)' "$hindsight_report_path")"

{
  printf '# Swarm Execution Queue Hindsight Normalization\n\n'
  printf -- "- Decision: \`%s\`\n" "$(jq -r '.decision' "$hindsight_report_path")"
  printf -- "- Queue tasks: \`%s\`\n" "$(jq '.summary.queue_task_count' "$hindsight_report_path")"
  printf -- "- Counterfactual candidates: \`%s\`\n" "$(jq '.summary.counterfactual_candidate_count' "$hindsight_report_path")"
  printf -- "- Fail-closed reasons: \`%s\`\n" "$(jq '.summary.fail_closed_reason_count' "$hindsight_report_path")"
  printf -- "- Degraded inputs: \`%s\`\n\n" "$(jq '.summary.degraded_input_count' "$hindsight_report_path")"

  if [[ "$(jq '.fail_closed_reasons | length' "$hindsight_report_path")" -ne 0 ]]; then
    printf '## Fail-Closed Reasons\n'
    jq -r '.fail_closed_reasons[] | "- `" + .kind + "` `" + .label + "`: " + .detail' "$hindsight_report_path"
    printf '\n'
  fi

  if [[ "$(jq '.degraded_inputs | length' "$hindsight_report_path")" -ne 0 ]]; then
    printf '## Degraded Inputs\n'
    jq -r '.degraded_inputs[] | "- `" + .kind + "` `" + .label + "`: " + .detail' "$hindsight_report_path"
    printf '\n'
  fi

  printf '## Rows\n'
  jq -r '.rows[] | "- `" + .task_id + "` `" + .fidelity_class + "` `" + .drift_class + "` `" + .confidence_band + "`"' "$hindsight_report_path"
} >"$report_path"

printf 'hindsight_input_json=%s\n' "$hindsight_input_path"
printf 'hindsight_report_json=%s\n' "$hindsight_report_path"
printf 'evidence_ledger_json=%s\n' "$evidence_ledger_path"
printf 'counterfactual_candidates_json=%s\n' "$counterfactual_candidates_path"
printf 'hindsight_report_md=%s\n' "$report_path"

if [[ "$(jq -r '.decision' "$hindsight_report_path")" == "fail_closed" ]]; then
  exit 42
fi
exit 0
