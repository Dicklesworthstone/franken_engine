#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
artifact_root="${SWARM_PROOF_BROKER_NO_MOCK_DRILL_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-proof-broker-no-mock-drill}"
run_id="${SWARM_PROOF_BROKER_NO_MOCK_DRILL_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_PROOF_BROKER_NO_MOCK_DRILL_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

fixture_json=""
input_json=""
mode="replay"
case_id=""
source_revision="${SWARM_PROOF_BROKER_NO_MOCK_DRILL_SOURCE_REVISION:-}"
declare -a claimed_paths=()

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/e2e/swarm_proof_broker_no_mock_drill.sh [OPTIONS]

Compose proof-broker lifecycle snapshots into a no-mock drill bundle and
fail-closed truth gate. Replay mode consumes preserved bundles. Live mode
captures local br/git/RCH metadata where available and fails closed if required
evidence is absent rather than substituting synthetic context.

Options:
  --fixture-json FILE    Single fixture case with sources.* snapshots.
  --input-json FILE      Drill input JSON.
  --mode MODE            replay or live. Default: replay.
  --case-id ID           Deterministic case id.
  --claimed-path PATH    Claimed dirty-path lane. May be repeated.
  --source-revision REV  Source revision recorded in artifacts.
  --output-dir DIR       Artifact directory.

Artifacts:
  proof_broker_lifecycle_bundle.json
  run_manifest.json
  events.jsonl
  commands.txt
  trace_ids.json
  request_capture.json
  equivalence_report.json
  artifact_index.json
  batch_plan.json
  chaos_scenarios.json
  operator_status_bundle.json
  truth_gate_report.json
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
    --mode)
      mode="${2:-}"
      shift 2
      ;;
    --case-id)
      case_id="${2:-}"
      shift 2
      ;;
    --claimed-path)
      claimed_paths+=("${2:-}")
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
  printf 'jq is required for swarm proof broker no-mock drill\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm proof broker no-mock drill\n' >&2
  exit 2
fi
case "$mode" in
  replay|live) ;;
  *)
    printf 'unsupported mode: %s\n' "$mode" >&2
    exit 64
    ;;
esac

if [[ -n "$fixture_json" ]]; then
  input_json="$fixture_json"
fi
if [[ "$mode" == "replay" ]]; then
  if [[ -z "$input_json" || ! -f "$input_json" ]]; then
    printf 'replay input JSON not found: %s\n' "${input_json:-}" >&2
    exit 64
  fi
  if ! jq empty "$input_json" >/dev/null 2>&1; then
    printf 'invalid input JSON: %s\n' "$input_json" >&2
    exit 64
  fi
fi
if [[ -z "$case_id" && -n "$input_json" && -f "$input_json" ]]; then
  case_id="$(jq -r '.case_id // "manual"' "$input_json")"
fi
if [[ -z "$case_id" ]]; then
  case_id="manual"
fi
if [[ -z "$source_revision" ]]; then
  source_revision="$(git -C "$root_dir" rev-parse --short HEAD 2>/dev/null || printf unknown)"
fi

mkdir -p "$run_dir"
input_path="${run_dir}/input.normalized.json"
bundle_path="${run_dir}/proof_broker_lifecycle_bundle.json"
bundle_tmp="${bundle_path}.tmp"
manifest_path="${run_dir}/run_manifest.json"
manifest_tmp="${manifest_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
trace_ids_path="${run_dir}/trace_ids.json"
request_capture_path="${run_dir}/request_capture.json"
equivalence_path="${run_dir}/equivalence_report.json"
artifact_index_path="${run_dir}/artifact_index.json"
batch_plan_path="${run_dir}/batch_plan.json"
chaos_path="${run_dir}/chaos_scenarios.json"
operator_status_path="${run_dir}/operator_status_bundle.json"
truth_gate_path="${run_dir}/truth_gate_report.json"
report_path="${run_dir}/report.md"

for artifact_path in \
  "$input_path" \
  "$bundle_path" \
  "$bundle_tmp" \
  "$manifest_path" \
  "$manifest_tmp" \
  "$events_path" \
  "$commands_path" \
  "$trace_ids_path" \
  "$request_capture_path" \
  "$equivalence_path" \
  "$artifact_index_path" \
  "$batch_plan_path" \
  "$chaos_path" \
  "$operator_status_path" \
  "$truth_gate_path" \
  "$report_path"; do
  if [[ -e "$artifact_path" ]]; then
    printf 'refusing to overwrite existing artifact: %s\n' "$artifact_path" >&2
    exit 73
  fi
done

: >"$events_path"
printf './scripts/e2e/swarm_proof_broker_no_mock_drill.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"

write_event() {
  local event="$1"
  local outcome="$2"
  local detail="$3"

  jq -nc \
    --arg schema_version "franken-engine.swarm-proof-broker-no-mock-drill.event.v1" \
    --arg component "swarm_proof_broker_no_mock_drill" \
    --arg event "$event" \
    --arg outcome "$outcome" \
    --arg detail "$detail" \
    --arg case_id "$case_id" \
    '{schema_version:$schema_version,component:$component,event:$event,outcome:$outcome,detail:$detail,case_id:$case_id}' >>"$events_path"
}

claimed_paths_json="$(printf '%s\n' "${claimed_paths[@]}" | jq -R . | jq -s .)"

if [[ "$mode" == "replay" ]]; then
  jq -cS . "$input_json" >"$input_path"
else
  tmp_live="${run_dir}/live.capture.tmp.json"
  br_snapshot='{"fresh":false,"source":"br-unavailable","issues":[]}'
  if command -v br >/dev/null 2>&1; then
    if br ready --json --no-auto-import --no-auto-flush >/tmp/swarm-proof-broker-br-ready.$$ 2>/dev/null; then
      br_snapshot="$(jq -cS '{fresh:true,source:"live-br-ready",issues:.}' /tmp/swarm-proof-broker-br-ready.$$)"
    fi
  fi
  git -C "$root_dir" status --porcelain 2>/dev/null | sed -E 's/^...//' | jq -R . | jq -s '{dirty_paths: map(select(length > 0))}' >/tmp/swarm-proof-broker-git.$$
  rch_snapshot='{"status":"missing","retrieval_complete":false,"local_fallback_observed":false}'
  if command -v rch >/dev/null 2>&1; then
    rch_snapshot='{"status":"present","retrieval_complete":false,"local_fallback_observed":false,"source":"live-rch-cli-present-no-summary"}'
  fi
  jq -n \
    --arg case_id "$case_id" \
    --argjson br "$br_snapshot" \
    --slurpfile git /tmp/swarm-proof-broker-git.$$ \
    --argjson rch "$rch_snapshot" \
    --argjson claimed "$claimed_paths_json" \
    '{
      case_id: $case_id,
      mode: "live",
      claimed_paths: $claimed,
      sources: {
        br: $br,
        agent_mail: {status: "missing", messages: [], reservations: []},
        git: ($git[0] // {dirty_paths: []}),
        rch: $rch,
        request_capture: {proof_requests: []},
        equivalence_report: {verdict: "missing"},
        artifact_index: {rows: []},
        batch_plan: {recommendations: []},
        chaos_scenarios: {scenario: {replayable: false}},
        operator_status: {summary_counts: {}, rows: []}
      }
    }' >"$tmp_live"
  jq -cS . "$tmp_live" >"$input_path"
fi

write_event "drill.started" "ok" "$mode"

jq -n \
  --slurpfile input "$input_path" \
  --arg schema_version "franken-engine.swarm-proof-broker-no-mock-drill.v1" \
  --arg truth_schema "franken-engine.swarm-proof-broker-truth-gate.v1" \
  --arg case_id "$case_id" \
  --arg mode "$mode" \
  --arg source_revision "$source_revision" \
  --arg input_path "$input_path" \
  --arg bundle_path "$bundle_path" \
  --arg manifest_path "$manifest_path" \
  --arg events_path "$events_path" \
  --arg commands_path "$commands_path" \
  --arg trace_ids_path "$trace_ids_path" \
  --arg request_capture_path "$request_capture_path" \
  --arg equivalence_path "$equivalence_path" \
  --arg artifact_index_path "$artifact_index_path" \
  --arg batch_plan_path "$batch_plan_path" \
  --arg chaos_path "$chaos_path" \
  --arg operator_status_path "$operator_status_path" \
  --arg truth_gate_path "$truth_gate_path" \
  --argjson cli_claimed_paths "$claimed_paths_json" '
  def arr($v): if ($v | type) == "array" then $v else [] end;
  def rows($v):
    if ($v.rows? | type) == "array" then $v.rows
    elif ($v.proofs? | type) == "array" then $v.proofs
    else []
    end;
  def proof_requests($sources): arr($sources.request_capture.proof_requests // $sources.request_capture.requests);
  def reservations($mail): arr($mail.reservations);
  def mail_present($mail): (($mail.status // "missing") != "missing") and ((arr($mail.messages) | length) > 0 or (reservations($mail) | length) > 0);
  def br_fresh($br):
    if ($br | has("fresh")) then $br.fresh == true
    elif ($br | has("snapshot_fresh")) then $br.snapshot_fresh == true
    else false
    end;
  def command_text($row):
    ($row.command // $row.requested_command // $row.normalized_command // (($row.normalized_command_argv // []) | join(" ")) // "");
  def shell_wrapped_cargo($cmd): ($cmd | test("^(bash|sh|zsh) -(lc|c) .*cargo "; "i"));
  def local_fallback($sources):
    (($sources.rch.local_fallback_observed // false) == true)
    or (($sources.rch.worker_posture // $sources.rch.rch_posture // "") == "local_fallback")
    or any(rows($sources.artifact_index)[]; ((.rch_posture // "") == "local_fallback") or ((.invalidation_reasons // []) | index("local_fallback_contamination")) != null)
    or any(arr($sources.operator_status.rows)[]; (.status // "") == "contaminated_refused");
  def incomplete_retrieval($sources):
    (($sources.rch | has("retrieval_complete")) and ($sources.rch.retrieval_complete == false))
    or any(rows($sources.artifact_index)[]; ((.invalidation_reasons // []) | index("incomplete_rch_artifact_retrieval")) != null or ((.artifact_bundle | has("complete")) and .artifact_bundle.complete == false));
  def stale_proof($sources):
    any(rows($sources.artifact_index)[]; ((.freshness // "") | IN("expired", "stale")) or ((.invalidation_reasons // []) | index("expired_ttl")) != null);
  def hidden_reuse_refusal($sources):
    (($sources.operator_status.hidden_reuse_refusal // false) == true)
    or (((rows($sources.artifact_index) | map(select((.reuse_eligible // false) != true)) | length) > 0) and (($sources.operator_status.summary_counts.reuse_refusal_count // 0) == 0));
  def overlaps($path; $claim): ($path | startswith($claim)) or ($claim | startswith($path));
  def dirty_outside($sources; $claims):
    (arr($sources.git.dirty_paths)) as $dirty
    | ((arr($sources.git.claimed_paths) + arr($claims))) as $claimed
    | [$dirty[] as $path | select((any($claimed[]; overlaps($path; .))) | not)];
  def under_specified_replay($sources):
    (($sources.chaos_scenarios.scenario | has("replayable")) and $sources.chaos_scenarios.scenario.replayable == false)
    or (($sources.chaos_scenarios.scenario | has("invariant_agreement")) and $sources.chaos_scenarios.scenario.invariant_agreement == false);
  def trace_ids($sources):
    {
      trace_ids: (
        [proof_requests($sources)[]? | .trace_id // empty]
        + [($sources.request_capture.trace_id // empty)]
      ) | unique,
      request_ids: [proof_requests($sources)[]? | .request_id // .proof_request_id // empty] | unique
    };

  ($input[0] // {}) as $doc
  | ($doc.sources // {}) as $sources
  | (($doc.claimed_paths // []) + $cli_claimed_paths) as $claims
  | (
      [
        if br_fresh($sources.br // {}) | not then "stale_br_bv_snapshot" else empty end,
        if mail_present($sources.agent_mail // {}) | not then "missing_agent_mail_evidence" else empty end,
        if local_fallback($sources) then "local_fallback_contamination" else empty end,
        if incomplete_retrieval($sources) then "incomplete_rch_artifact_retrieval" else empty end,
        if (dirty_outside($sources; $claims) | length) > 0 then "dirty_paths_outside_lane" else empty end,
        if hidden_reuse_refusal($sources) then "hidden_reuse_refusal" else empty end,
        if any(proof_requests($sources)[]; shell_wrapped_cargo(command_text(.))) or (($sources.rch.unsupported_shell_wrapped_cargo // false) == true) then "unsupported_shell_wrapped_cargo" else empty end,
        if stale_proof($sources) then "stale_proof_rejection" else empty end,
        if under_specified_replay($sources) then "under_specified_replay_bundle" else empty end
      ] | unique
    ) as $failures
  | ($failures | length) == 0 as $passed
  | {
      schema_version: $schema_version,
      case_id: $case_id,
      mode: $mode,
      source_revision: $source_revision,
      decision: (if $passed then "pass" else "fail_closed" end),
      fail_closed_reasons: $failures,
      trace_ids: trace_ids($sources),
      component_summaries: {
        request_capture_count: (proof_requests($sources) | length),
        equivalence_verdict: ($sources.equivalence_report.verdict // "missing"),
        artifact_rows: (rows($sources.artifact_index) | length),
        batch_recommendations: (arr($sources.batch_plan.recommendations) | length),
        chaos_replayable: ($sources.chaos_scenarios.scenario.replayable // false),
        operator_status: ($sources.operator_status.overall_status // "missing")
      },
      truth_gate_report: {
        schema_version: $truth_schema,
        case_id: $case_id,
        decision: (if $passed then "pass" else "fail_closed" end),
        fail_closed_reasons: $failures,
        dirty_paths_outside_lane: dirty_outside($sources; $claims),
        no_hidden_green_status: (($sources.operator_status.hidden_green_status // false) == false),
        no_mock_attestation: {
          replay_mode_uses_preserved_bundle: ($mode == "replay"),
          live_mode_uses_synthetic_substitution: false,
          executes_cargo: false,
          executes_rch: false,
          mutates_live_queue: false
        }
      },
      artifacts: {
        input_normalized_json: $input_path,
        proof_broker_lifecycle_bundle_json: $bundle_path,
        run_manifest_json: $manifest_path,
        events_jsonl: $events_path,
        commands_txt: $commands_path,
        trace_ids_json: $trace_ids_path,
        request_capture_json: $request_capture_path,
        equivalence_report_json: $equivalence_path,
        artifact_index_json: $artifact_index_path,
        batch_plan_json: $batch_plan_path,
        chaos_scenarios_json: $chaos_path,
        operator_status_bundle_json: $operator_status_path,
        truth_gate_report_json: $truth_gate_path
      },
      sources: $sources,
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

bundle_hash="$(jq -cS '{case_id,mode,decision,fail_closed_reasons,trace_ids,component_summaries,truth_gate_report}' "$bundle_tmp" | sha256sum | awk '{print $1}')"
jq --arg bundle_hash "$bundle_hash" '. + {bundle_hash: $bundle_hash}' "$bundle_tmp" >"$bundle_path"

jq '.trace_ids' "$bundle_path" >"$trace_ids_path"
jq '.sources.request_capture // {proof_requests: []}' "$bundle_path" >"$request_capture_path"
jq '.sources.equivalence_report // {verdict: "missing"}' "$bundle_path" >"$equivalence_path"
jq '.sources.artifact_index // {rows: []}' "$bundle_path" >"$artifact_index_path"
jq '.sources.batch_plan // {recommendations: []}' "$bundle_path" >"$batch_plan_path"
jq '.sources.chaos_scenarios // {scenario: {replayable: false}}' "$bundle_path" >"$chaos_path"
jq '.sources.operator_status // {rows: []}' "$bundle_path" >"$operator_status_path"
jq '.truth_gate_report' "$bundle_path" >"$truth_gate_path"

decision="$(jq -r '.decision' "$bundle_path")"
reason_summary="$(jq -r '.fail_closed_reasons | join(",")' "$bundle_path")"

jq -n \
  --arg schema_version "franken-engine.swarm-proof-broker-no-mock-drill-run-manifest.v1" \
  --arg component "swarm_proof_broker_no_mock_drill" \
  --arg case_id "$case_id" \
  --arg mode "$mode" \
  --arg source_revision "$source_revision" \
  --arg decision "$decision" \
  --arg reason_summary "$reason_summary" \
  --arg bundle_hash "$bundle_hash" \
  --arg bundle_path "$bundle_path" \
  --arg truth_gate_path "$truth_gate_path" \
  '{
    schema_version: $schema_version,
    component: $component,
    case_id: $case_id,
    mode: $mode,
    source_revision: $source_revision,
    decision: $decision,
    fail_closed_reason_summary: $reason_summary,
    bundle_hash: $bundle_hash,
    proof_broker_lifecycle_bundle_json: $bundle_path,
    truth_gate_report_json: $truth_gate_path,
    executed_heavy_work: false
  }' >"$manifest_tmp"
mv "$manifest_tmp" "$manifest_path"

write_event "drill.completed" "$decision" "$reason_summary"

{
  printf '# Swarm Proof Broker No-Mock Drill\n\n'
  printf -- "- case_id: \`%s\`\n" "$case_id"
  printf -- "- mode: \`%s\`\n" "$mode"
  printf -- "- decision: \`%s\`\n" "$decision"
  printf -- "- bundle_hash: \`%s\`\n" "$bundle_hash"
  if [[ -n "$reason_summary" ]]; then
    printf -- "- fail_closed_reasons: \`%s\`\n" "$reason_summary"
  fi
} >"$report_path"

if [[ "$decision" == "fail_closed" ]]; then
  exit 42
fi
exit 0
