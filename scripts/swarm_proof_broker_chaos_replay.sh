#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
artifact_root="${SWARM_PROOF_BROKER_CHAOS_REPLAY_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-proof-broker-chaos-replay}"
run_id="${SWARM_PROOF_BROKER_CHAOS_REPLAY_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_PROOF_BROKER_CHAOS_REPLAY_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

fixture_json=""
input_json=""
case_id=""
source_revision="${SWARM_PROOF_BROKER_CHAOS_REPLAY_SOURCE_REVISION:-}"

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_proof_broker_chaos_replay.sh [OPTIONS]

Generate replayable proof-broker chaos scenarios from preserved proof-request
evidence and deterministic deltas. This script never executes the replayed
commands, Cargo, RCH, br, or Agent Mail mutations.

Options:
  --fixture-json FILE    Single fixture case with original_evidence and deltas.
  --input-json FILE      Chaos scenario input JSON.
  --case-id ID           Deterministic case id.
  --source-revision REV  Source revision recorded in artifacts.
  --output-dir DIR       Artifact directory.

Artifacts:
  chaos_replay_bundle.json
  scenarios.jsonl
  replay_commands.sh
  classifier_input.json
  artifact_index_input.json
  batch_planner_input.json
  operator_status_input.json
  events.jsonl
  commands.txt
  report.md
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --fixture-json)
      fixture_json="${2:-}"
      shift 2
      ;;
    --input-json)
      input_json="${2:-}"
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
      printf 'unknown argument: %s\n' "$1" >&2
      usage
      exit 64
      ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm proof broker chaos replay\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm proof broker chaos replay\n' >&2
  exit 2
fi

if [[ -n "$fixture_json" ]]; then
  input_json="$fixture_json"
fi
if [[ -z "$input_json" || ! -f "$input_json" ]]; then
  printf 'input JSON not found: %s\n' "${input_json:-}" >&2
  exit 64
fi
if ! jq empty "$input_json" >/dev/null 2>&1; then
  printf 'invalid input JSON: %s\n' "$input_json" >&2
  exit 64
fi
if [[ -z "$case_id" ]]; then
  case_id="$(jq -r '.case_id // "manual"' "$input_json")"
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
input_path="${run_dir}/input.normalized.json"
bundle_path="${run_dir}/chaos_replay_bundle.json"
bundle_tmp="${bundle_path}.tmp"
scenarios_jsonl="${run_dir}/scenarios.jsonl"
replay_commands_path="${run_dir}/replay_commands.sh"
classifier_input_path="${run_dir}/classifier_input.json"
artifact_index_input_path="${run_dir}/artifact_index_input.json"
batch_planner_input_path="${run_dir}/batch_planner_input.json"
operator_status_input_path="${run_dir}/operator_status_input.json"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"

for artifact_path in \
  "$input_path" \
  "$bundle_path" \
  "$bundle_tmp" \
  "$scenarios_jsonl" \
  "$replay_commands_path" \
  "$classifier_input_path" \
  "$artifact_index_input_path" \
  "$batch_planner_input_path" \
  "$operator_status_input_path" \
  "$events_path" \
  "$commands_path" \
  "$report_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/swarm_proof_broker_chaos_replay.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  local event="$1"
  local outcome="$2"
  local detail="$3"

  jq -nc \
    --arg schema_version "franken-engine.swarm-proof-broker-chaos-replay.event.v1" \
    --arg component "swarm_proof_broker_chaos_replay" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg detail "$detail" \
    --arg case_id "$case_id" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail,case_id:$case_id}' >>"$events_path"
}

jq -cS . "$input_json" >"$input_path"
write_event "chaos_replay.started" "ok" "$case_id"

jq -n \
  --slurpfile input "$input_path" \
  --arg schema_version "franken-engine.swarm-proof-broker-chaos-replay.v1" \
  --arg case_id "$case_id" \
  --arg source_revision "$source_revision" \
  --arg input_path "$input_path" \
  --arg bundle_path "$bundle_path" \
  --arg scenarios_jsonl "$scenarios_jsonl" \
  --arg replay_commands_path "$replay_commands_path" \
  --arg classifier_input_path "$classifier_input_path" \
  --arg artifact_index_input_path "$artifact_index_input_path" \
  --arg batch_planner_input_path "$batch_planner_input_path" \
  --arg operator_status_input_path "$operator_status_input_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg report_path "$report_path" '
  def arr($v): if ($v | type) == "array" then $v else [] end;
  def evidence_paths($row): arr($row.evidence_paths) + arr($row.source_evidence);
  def first_request($doc): arr($doc.original_evidence.proof_requests)[0] // {};
  def command($row): ($row.command // ($row.normalized_command_argv // [] | join(" ")) // "");
  def base_fp($doc): (first_request($doc).proof_fingerprint // $doc.proof_fingerprint // ("fp-" + $case_id));
  def agent_mail_status($doc): ($doc.original_evidence.agent_mail.status // "present");
  def rch_posture($doc): ($doc.original_evidence.rch.worker_posture // $doc.original_evidence.rch.rch_posture // "remote");
  def dirty_changed($doc): arr($doc.deltas.changed_dirty_paths) | length > 0;
  def dependency_changed($doc): arr($doc.deltas.changed_dependency_roots) | length > 0;
  def stale_artifact($doc): (($doc.deltas.artifact_freshness // "") | IN("expired", "stale"));
  def local_fallback($doc): (($doc.deltas.rch_worker_posture // rch_posture($doc)) == "local_fallback");
  def duplicate_count($doc): (($doc.deltas.duplicate_request_count // 1) | tonumber);
  def has_enough_evidence($doc):
    (arr($doc.original_evidence.proof_requests) | length) > 0
    and all(arr($doc.original_evidence.proof_requests)[]; (command(.) | length) > 0 and (evidence_paths(.) | length) > 0)
    and ((agent_mail_status($doc)) != "missing")
    and (($doc.original_evidence.rch.status // "present") != "missing");
  def reason_codes($doc):
    [
      if has_enough_evidence($doc) | not then "insufficient_source_evidence" else empty end,
      if duplicate_count($doc) > 1 then "duplicate_command_burst" else empty end,
      if stale_artifact($doc) then "expired_ttl" else empty end,
      if dirty_changed($doc) then "dirty_lane_mismatch" else empty end,
      if dependency_changed($doc) then "changed_dependency_root" else empty end,
      if local_fallback($doc) then "local_fallback_contamination" else empty end,
      if (agent_mail_status($doc) | IN("degraded", "degraded_read_only", "outage")) then "agent_mail_degraded_capture" else empty end
    ];
  def classifier_verdict($doc):
    if has_enough_evidence($doc) | not then "fail_closed"
    elif local_fallback($doc) then "reuse_refused"
    elif dirty_changed($doc) then "reuse_refused"
    elif dependency_changed($doc) then "rerun_required"
    else "reuse_allowed"
    end;
  def artifact_decision($doc):
    if stale_artifact($doc) or local_fallback($doc) or dependency_changed($doc) then "reuse_refused" else "reuse_allowed" end;
  def batch_action($doc):
    if has_enough_evidence($doc) | not then "human_review"
    elif duplicate_count($doc) > 1 then "coalesce"
    elif stale_artifact($doc) then "rerun_later"
    else "rerun_now"
    end;
  def operator_status($doc):
    if has_enough_evidence($doc) | not then "fail_closed"
    elif local_fallback($doc) then "contaminated_refused"
    elif stale_artifact($doc) then "stale_refused"
    elif dirty_changed($doc) or dependency_changed($doc) then "reuse_refused"
    elif duplicate_count($doc) > 1 then "coalesced"
    elif (agent_mail_status($doc) | IN("degraded", "degraded_read_only", "outage")) then "agent_mail_degraded_visible"
    else "pending"
    end;
  def perturbed_requests($doc):
    first_request($doc) as $base
    | [range(0; duplicate_count($doc)) as $idx
        | $base
        + {
            request_id: (($base.request_id // "req-chaos") + "-" + ($idx | tostring)),
            proof_fingerprint: base_fp($doc),
            requested_at_offset_ms: (($doc.deltas.request_timing_offsets_ms // [0])[$idx] // ($idx * 25)),
            dirty_paths: (arr($base.dirty_paths) + arr($doc.deltas.changed_dirty_paths)),
            dependency_closure_roots: (arr($base.dependency_closure_roots) + arr($doc.deltas.changed_dependency_roots)),
            rch_posture: ($doc.deltas.rch_worker_posture // rch_posture($doc))
          }
      ];
  def classifier_input($doc):
    first_request($doc) as $base
    | {
        candidate: $base,
        requested: ($base + {
          dirty_paths: (arr($base.dirty_paths) + arr($doc.deltas.changed_dirty_paths)),
          dependency_closure_roots: (arr($base.dependency_closure_roots) + arr($doc.deltas.changed_dependency_roots)),
          rch_posture: ($doc.deltas.rch_worker_posture // rch_posture($doc)),
          local_fallback_observed: local_fallback($doc)
        })
      };
  def artifact_index_input($doc):
    first_request($doc) as $base
    | {
        case_id: $case_id,
        proofs: [
          {
            proof_fingerprint: base_fp($doc),
            verdict_status: "passed",
            now_epoch: 2000,
            expires_at_epoch: (if stale_artifact($doc) then 1000 else 3000 end),
            source_revision: ($base.source_revision // "fixture-source"),
            expected_source_revision: ($base.source_revision // "fixture-source"),
            dependency_closure_fingerprint: (if dependency_changed($doc) then "changed" else "base" end),
            expected_dependency_closure_fingerprint: "base",
            rch_posture: ($doc.deltas.rch_worker_posture // rch_posture($doc)),
            local_fallback_observed: local_fallback($doc),
            retrieval_complete: true,
            artifact_bundle: {complete: true, artifacts: ["proof.log", "metadata.json"]},
            artifact_paths: {
              preserved_evidence: ($doc.original_evidence.bundle_path // "fixtures/preserved/proof_bundle.json")
            }
          }
        ]
      };
  def batch_planner_input($doc):
    {
      case_id: $case_id,
      requests: perturbed_requests($doc),
      artifact_index: [
        {
          proof_fingerprint: base_fp($doc),
          reuse_eligible: (artifact_decision($doc) == "reuse_allowed"),
          freshness: (if stale_artifact($doc) then "expired" else "fresh" end),
          invalidation_reasons: (reason_codes($doc) | map(select(. == "expired_ttl" or . == "local_fallback_contamination" or . == "changed_dependency_root")))
        }
      ],
      workers: [
        {
          worker_id: "worker-chaos-a",
          target_isolation: "compatible",
          warm_cache_fingerprints: [base_fp($doc)]
        }
      ],
      fairness_debt: [],
      operator_policy: {conflict: false}
    };
  def operator_status_input($doc):
    {
      case_id: $case_id,
      proof_requests: perturbed_requests($doc),
      artifact_index: batch_planner_input($doc).artifact_index,
      batch_recommendations: [
        {
          recommendation_id: ("rec-" + $case_id),
          request_id: ((perturbed_requests($doc)[0].request_id // "req-chaos")),
          proof_fingerprint: base_fp($doc),
          action: batch_action($doc),
          evidence_paths: ["fixtures/" + $case_id + "/batch_plan.json"]
        }
      ],
      equivalence_receipts: [
        {
          classifier_hash: ("classifier-" + $case_id),
          proof_fingerprint: base_fp($doc),
          verdict: classifier_verdict($doc),
          reuse_eligible: (classifier_verdict($doc) == "reuse_allowed"),
          reason_codes: (reason_codes($doc) | map(select(. != "duplicate_command_burst" and . != "agent_mail_degraded_capture"))),
          requested: first_request($doc),
          artifact_paths: {classifier_report: "fixtures/" + $case_id + "/equivalence_report.json"}
        }
      ],
      fairness_debt: [],
      operator_policy: {
        panel_claims_mutation_authority: false,
        hide_stale_evidence: false,
        omit_refusal_reasons: false
      }
    };
  def replay_commands:
    [
      "./scripts/swarm_proof_equivalence_classifier.sh --fixture-json classifier_input.json --output-dir replay/classifier",
      "./scripts/swarm_proof_artifact_index.sh --fixture-json artifact_index_input.json --output-dir replay/artifact_index",
      "./scripts/swarm_proof_batch_planner.sh --fixture-json batch_planner_input.json --output-dir replay/batch_planner",
      "./scripts/swarm_proof_broker_operator_status.sh --fixture-json operator_status_input.json --output-dir replay/operator_status"
    ];

  ($input[0] // {}) as $doc
  | (has_enough_evidence($doc)) as $replayable
  | (reason_codes($doc)) as $reasons
  | {
      schema_version: $schema_version,
      case_id: $case_id,
      source_revision: $source_revision,
      decision: (if $replayable then "pass" else "fail_closed" end),
      fail_closed_reasons: (if $replayable then [] else ["insufficient_source_evidence"] end),
      scenario: {
        scenario_id: ("chaos-" + $case_id),
        scenario_kind: ($doc.scenario_kind // "manual"),
        replayable: $replayable,
        reason_codes: $reasons,
        original_evidence: ($doc.original_evidence // {}),
        deterministic_deltas: ($doc.deltas // {}),
        perturbed_requests: perturbed_requests($doc),
        expected_invariants: {
          classifier_verdict: classifier_verdict($doc),
          artifact_index_decision: artifact_decision($doc),
          batch_planner_action: batch_action($doc),
          operator_status_projection: operator_status($doc),
          agent_mail_status: agent_mail_status($doc),
          exact_replay_commands_present: true
        },
        invariant_agreement: (
          if $replayable | not then false
          elif local_fallback($doc) then classifier_verdict($doc) == "reuse_refused" and artifact_decision($doc) == "reuse_refused" and operator_status($doc) == "contaminated_refused"
          elif stale_artifact($doc) then artifact_decision($doc) == "reuse_refused" and batch_action($doc) == "rerun_later" and operator_status($doc) == "stale_refused"
          elif dirty_changed($doc) or dependency_changed($doc) then classifier_verdict($doc) != "reuse_allowed" and operator_status($doc) == "reuse_refused"
          elif duplicate_count($doc) > 1 then batch_action($doc) == "coalesce" and operator_status($doc) == "coalesced"
          else true
          end
        ),
        replay_commands: replay_commands,
        component_inputs: {
          classifier: classifier_input($doc),
          artifact_index: artifact_index_input($doc),
          batch_planner: batch_planner_input($doc),
          operator_status: operator_status_input($doc)
        }
      },
      artifact_paths: {
        input_normalized_json: $input_path,
        chaos_replay_bundle_json: $bundle_path,
        scenarios_jsonl: $scenarios_jsonl,
        replay_commands_sh: $replay_commands_path,
        classifier_input_json: $classifier_input_path,
        artifact_index_input_json: $artifact_index_input_path,
        batch_planner_input_json: $batch_planner_input_path,
        operator_status_input_json: $operator_status_input_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        report_md: $report_path
      },
      non_mutation_attestation: {
        runs_cargo: false,
        runs_rch: false,
        mutates_br: false,
        sends_agent_mail: false,
        mutates_remote_workers: false,
        changes_live_queue_policy: false
      }
    }
  ' >"$bundle_tmp"

scenario_hash="$(jq -cS '{case_id,decision,fail_closed_reasons,scenario:{scenario_kind:.scenario.scenario_kind,reason_codes:.scenario.reason_codes,deterministic_deltas:.scenario.deterministic_deltas,perturbed_requests:.scenario.perturbed_requests,expected_invariants:.scenario.expected_invariants,replay_commands:.scenario.replay_commands}}' "$bundle_tmp" | sha256sum | awk '{print $1}')"
jq --arg scenario_hash "$scenario_hash" '.scenario += {scenario_hash: $scenario_hash}' "$bundle_tmp" >"$bundle_path"

jq -c '.scenario' "$bundle_path" >"$scenarios_jsonl"
jq -c '.scenario.component_inputs.classifier' "$bundle_path" >"$classifier_input_path"
jq -c '.scenario.component_inputs.artifact_index' "$bundle_path" >"$artifact_index_input_path"
jq -c '.scenario.component_inputs.batch_planner' "$bundle_path" >"$batch_planner_input_path"
jq -c '.scenario.component_inputs.operator_status' "$bundle_path" >"$operator_status_input_path"
{
  printf '#!/usr/bin/env bash\n'
  printf 'set -euo pipefail\n\n'
  printf '# Replay commands are emitted for operators; this generator does not execute them.\n'
  jq -r '.scenario.replay_commands[]' "$bundle_path"
} >"$replay_commands_path"
chmod +x "$replay_commands_path"

decision="$(jq -r '.decision' "$bundle_path")"
reason_summary="$(jq -r '.fail_closed_reasons | join(",")' "$bundle_path")"
write_event "chaos_replay.completed" "$decision" "$reason_summary"

{
  printf '# Swarm Proof Broker Chaos Replay\n\n'
  printf -- "- case_id: \`%s\`\n" "$case_id"
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- scenario_hash: \`%s\`\n" "$scenario_hash"
  printf -- "- scenario_kind: \`%s\`\n" "$(jq -r '.scenario.scenario_kind' "$bundle_path")"
  if [[ -n "$reason_summary" ]]; then
    printf -- "- fail_closed_reasons: \`%s\`\n" "$reason_summary"
  fi
} >"$report_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
exit 0
