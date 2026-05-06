#!/usr/bin/env bash
set -euo pipefail

artifact_root="${SWARM_AGENT_CAUSAL_TRACE_GRAPH_ARTIFACT_ROOT:-${TMPDIR:-/tmp}/franken-engine-swarm-agent-causal-trace-graph}"
run_id="${SWARM_AGENT_CAUSAL_TRACE_GRAPH_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${SWARM_AGENT_CAUSAL_TRACE_GRAPH_RUN_DIR:-${artifact_root}/${run_id}}"
original_args=("$@")

normalized_events_json=""
bead_id_override=""
agent_name_override=""
source_revision_override=""

usage() {
  cat >&2 <<'EOF'
Usage: ./scripts/swarm_agent_causal_trace_graph.sh --normalized-events-json FILE [OPTIONS]

Builds a deterministic, fixture-fed causal graph and anomaly report from a
SWARM-CTRL-XVI normalized causal trace event set. The script does not query
live br, Agent Mail, rch, git, cargo, or remote workers.

Required:
  --normalized-events-json FILE

Optional:
  --bead-id ID
  --agent-name NAME
  --source-revision REV
  --output-dir DIR

Artifacts:
  swarm_agent_causal_trace_graph.json
  swarm_agent_causal_trace_anomalies.json
  events.jsonl
  commands.txt
  report.md

Exit codes:
  0  graph is replayable; decision may be pass or degraded
  42 fail-closed anomaly detected
  64 invalid required input or malformed JSON
EOF
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --normalized-events-json)
      normalized_events_json="${2:-}"
      shift 2
      ;;
    --bead-id)
      bead_id_override="${2:-}"
      shift 2
      ;;
    --agent-name)
      agent_name_override="${2:-}"
      shift 2
      ;;
    --source-revision)
      source_revision_override="${2:-}"
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

if [[ -z "$normalized_events_json" ]]; then
  printf 'swarm agent causal trace graph requires --normalized-events-json\n' >&2
  usage
  exit 64
fi
if ! command -v jq >/dev/null 2>&1; then
  printf 'jq is required for swarm agent causal trace graphing\n' >&2
  exit 2
fi
if ! command -v sha256sum >/dev/null 2>&1; then
  printf 'sha256sum is required for swarm agent causal trace graphing\n' >&2
  exit 2
fi
if [[ ! -f "$normalized_events_json" ]]; then
  printf 'normalized event set does not exist: %s\n' "$normalized_events_json" >&2
  exit 64
fi
if ! jq -e '
  type == "object"
  and (.schema_version == "franken-engine.swarm-agent-causal-trace-event-set.v1")
  and (.events | type == "array")
' "$normalized_events_json" >/dev/null; then
  printf 'normalized event set must match franken-engine.swarm-agent-causal-trace-event-set.v1\n' >&2
  exit 64
fi

mkdir -p "$run_dir"
graph_path="${run_dir}/swarm_agent_causal_trace_graph.json"
graph_tmp="${graph_path}.tmp"
anomaly_report_path="${run_dir}/swarm_agent_causal_trace_anomalies.json"
anomaly_report_tmp="${anomaly_report_path}.tmp"
events_path="${run_dir}/events.jsonl"
commands_path="${run_dir}/commands.txt"
report_path="${run_dir}/report.md"
raw_nodes_jsonl="${run_dir}/nodes.raw.jsonl"
nodes_jsonl="${run_dir}/nodes.jsonl"
raw_edges_jsonl="${run_dir}/edges.raw.jsonl"
edges_jsonl="${run_dir}/edges.jsonl"
raw_anomalies_jsonl="${run_dir}/anomalies.raw.jsonl"
anomalies_jsonl="${run_dir}/anomalies.jsonl"

printf './scripts/swarm_agent_causal_trace_graph.sh' >"$commands_path"
for arg in "${original_args[@]}"; do
  printf ' %q' "$arg" >>"$commands_path"
done
printf '\n' >>"$commands_path"
: >"$events_path"
: >"$raw_nodes_jsonl"
: >"$nodes_jsonl"
: >"$raw_edges_jsonl"
: >"$edges_jsonl"
: >"$raw_anomalies_jsonl"
: >"$anomalies_jsonl"

emit_event() {
  local event="$1"
  local detail="$2"
  jq -cn --arg event "$event" --arg detail "$detail" \
    '{schema_version:"franken-engine.swarm-agent-causal-trace-graph-producer-event.v1", event:$event, detail:$detail}' >>"$events_path"
}

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

hash_jsonl_rows() {
  local input="$1"
  local output="$2"
  local field_name="$3"
  local row hash
  : >"$output"
  while IFS= read -r row || [[ -n "$row" ]]; do
    [[ -n "$row" ]] || continue
    hash="$(printf '%s' "$row" | sha256sum | awk '{print $1}')"
    jq -cS --arg field_name "$field_name" --arg hash "sha256:${hash}" \
      '. + {($field_name): $hash}' <<<"$row" >>"$output"
  done <"$input"
}

event_set_decision="$(jq -r '.decision // "pass"' "$normalized_events_json")"
bead_id="${bead_id_override:-$(jq -r '.bead_id // ""' "$normalized_events_json")}"
agent_name="${agent_name_override:-$(jq -r '.agent_name // ""' "$normalized_events_json")}"
source_revision="${source_revision_override:-$(jq -r '.source_revision // ""' "$normalized_events_json")}"
trace_id="sha256:$(hash_file "$normalized_events_json")"

if [[ -z "$bead_id" || -z "$agent_name" || -z "$source_revision" ]]; then
  printf 'normalized event set must provide bead_id, agent_name, and source_revision, or explicit overrides must be supplied\n' >&2
  exit 64
fi

emit_event "graph_started" "$bead_id"

jq -cS --arg bead_id "$bead_id" --arg source_revision "$source_revision" '
  def clean: tostring | gsub("[^A-Za-z0-9_.:-]"; "_");
  def node_id($e):
    "node:" + (($e.event_type // "event") | clean) + ":" + (($e.event_id // "unknown") | clean);
  .events[]
  | {
      node_id: node_id(.),
      node_type: (.event_type // "event"),
      event_id: (.event_id // ""),
      bead_id: (.bead_id // $bead_id),
      agent_name: (.agent_name // ""),
      thread_id: (.thread_id // ""),
      source_revision: (.source_revision // $source_revision),
      source_path: (.source_path // ""),
      artifact_path: (.artifact_path // ""),
      content_hash: (.content_hash // ""),
      observed_at: (.observed_at // ""),
      label: ((.event_type // "event") + ":" + (.event_id // "unknown")),
      payload: (.payload // {})
    }
' "$normalized_events_json" >"$raw_nodes_jsonl"
hash_jsonl_rows "$raw_nodes_jsonl" "$nodes_jsonl" "node_hash"

jq -cS --arg bead_id "$bead_id" '
  def clean: tostring | gsub("[^A-Za-z0-9_.:>/-]"; "_");
  def node_id($e):
    "node:" + (($e.event_type // "event") | clean) + ":" + (($e.event_id // "unknown") | clean);
  def events($type): [.events[] | select((.event_type // "") == $type)];
  def text($e):
    [
      $e.payload.subject,
      $e.payload.body_md,
      $e.payload.body,
      $e.payload.message,
      $e.payload.detail,
      $e.decision
    ] | map(. // "") | join(" ");
  def same_agent($left; $right):
    (($left.agent_name // $left.payload.agent_name // $left.payload.name // $left.payload.from // "") as $l
      | ($right.agent_name // $right.payload.agent_name // $right.payload.name // $right.payload.from // "") as $r
      | ($l != "" and $r != "" and $l == $r));
  def edge($type; $from; $to; $detail):
    {
      edge_id: (("edge:" + $type + ":" + node_id($from) + ">" + node_id($to)) | clean),
      edge_type: $type,
      from_node_id: node_id($from),
      to_node_id: node_id($to),
      bead_id: $bead_id,
      source_event_ids: [($from.event_id // ""), ($to.event_id // "")],
      detail: $detail
    };
  events("bead_state") as $beads
  | events("agent_profile") as $profiles
  | events("mail_message") as $messages
  | events("file_reservation") as $reservations
  | events("git_commit") as $commits
  | events("validation_command") as $validations
  | events("rch_proof_artifact") as $rch
  | events("operator_status") as $operator_status
  | ($beads[0] // empty) as $bead
  | [
      ($profiles[]? as $profile
        | $messages[]?
        | select(same_agent($profile; .))
        | edge("agent_introduced"; $profile; .; "agent profile links to Agent Mail claim or introduction evidence")),
      ($messages[]?
        | select(text(.) | test("claim|claimed|claiming|intro|introduced"; "i"))
        | edge("bead_claimed"; .; $bead; "Agent Mail claim or introduction links to bead state")),
      ($reservations[]?
        | edge("reservation_covers_path"; $bead; .; "bead claim links to file reservation scope")),
      ($messages[]?
        | select((.payload.ack_required // false) == true)
        | select(((.payload.ack_ts // .payload.acknowledged_at // .payload.acknowledged_at_utc // "") | length) > 0 or ((.payload.acknowledged // false) == true))
        | edge("message_acknowledged"; .; $bead; "ack_required Agent Mail message includes acknowledgement evidence")),
      ($validations[]? as $validation
        | $rch[]?
        | edge("validation_proves_closeout"; $validation; .; "validation command links to RCH proof artifact")),
      ($validations[]?
        | select(($rch | length) == 0)
        | edge("validation_proves_closeout"; .; $bead; "validation command links directly to bead closeout evidence")),
      ($rch[]?
        | edge("validation_proves_closeout"; .; $bead; "RCH proof artifact links to bead closeout evidence")),
      ($commits[]?
        | edge("commit_closes_bead"; .; $bead; "closeout commit links to closed bead state")),
      ($operator_status[]?
        | edge("operator_status_summarizes_trace"; .; $bead; "operator status summarizes causal trace state")),
      (.events[]?
        | select(((.content_hash // "") | length) > 0)
        | edge("artifact_hashes_source"; .; $bead; "event content hash anchors source evidence"))
    ]
  | sort_by(.edge_id)
  | unique_by(.edge_id)
  | .[]
' "$normalized_events_json" >"$raw_edges_jsonl"
hash_jsonl_rows "$raw_edges_jsonl" "$edges_jsonl" "edge_hash"

jq -cS --arg bead_id "$bead_id" --arg agent_name "$agent_name" '
  def events($type): [.events[] | select((.event_type // "") == $type)];
  def root_fail($code): any((.fail_closed_reasons // [])[]?; (.code // "") == $code);
  def root_degraded($code): any((.degraded_reasons // [])[]?; (.code // "") == $code);
  def source_missing($needle):
    any((.degraded_reasons // [])[]?; (.code // "") == "optional_snapshot_missing" and ((.message // "") | test($needle; "i")));
  def text($e):
    [
      $e.payload.subject,
      $e.payload.body_md,
      $e.payload.body,
      $e.payload.message,
      $e.payload.detail,
      $e.decision
    ] | map(. // "") | join(" ");
  def claim_messages:
    [events("mail_message")[] | select(text(.) | test("claim|claimed|claiming|intro|introduced"; "i"))];
  def bead_state:
    (events("bead_state")[0] // {});
  def closed_bead:
    ((bead_state.payload.status // bead_state.decision // "") == "closed");
  def anomaly($class; $severity; $evidence; $detail; $remediation):
    {
      anomaly_class: $class,
      severity: $severity,
      bead_id: $bead_id,
      evidence_event_ids: $evidence,
      detail: $detail,
      remediation: $remediation
    };
  [
    (if ((claim_messages | length) == 0) then
      anomaly(
        "missing_claim_message";
        (if source_missing("Agent Mail messages") then "degraded" else "fail_closed" end);
        [];
        "No Agent Mail claim or introduction message was linked to the bead";
        "Capture the bead thread snapshot, or file a manual claim note before trusting the handoff"
      )
    else empty end),
    (if root_fail("missing_reservation_for_dirty_path") then
      anomaly(
        "missing_reservation_for_dirty_path";
        "fail_closed";
        [events("bead_state")[0].event_id // ""];
        "A dirty path lacks matching reservation evidence";
        "Reserve or release the path explicitly before accepting the trace"
      )
    else empty end),
    (if root_fail("reservation_without_matching_bead_scope") then
      anomaly(
        "reservation_without_matching_bead_scope";
        "fail_closed";
        [events("file_reservation")[]?.event_id];
        "A reservation path is outside the declared bead write set";
        "Align the declared write set with the reservation scope or split the bead"
      )
    else empty end),
    (if root_fail("local_rch_fallback_contaminates_remote_proof") or any(events("rch_proof_artifact")[]?; ((.payload.local_fallback_detected // false) == true) or (((.payload.stderr // .payload.stdout // .payload.detail // "") | test("local fallback|\\[RCH\\] local|running locally"; "i")))) then
      anomaly(
        "local_rch_fallback_contaminates_remote_proof";
        "fail_closed";
        [events("rch_proof_artifact")[]?.event_id];
        "RCH proof snapshot includes a rejected local fallback marker";
        "Reject the proof and rerun validation only after remote routing is healthy"
      )
    else empty end),
    (if root_fail("closed_bead_missing_commit") or (closed_bead and ((events("git_commit") | length) == 0)) then
      anomaly(
        "closed_bead_missing_commit";
        "fail_closed";
        [events("bead_state")[0].event_id // ""];
        "Closed bead lacks linked closeout commit evidence";
        "Capture the closeout commit mapping before accepting the bead closure"
      )
    else empty end),
    (if root_fail("closed_bead_missing_validation_evidence") or (closed_bead and ((events("validation_command") | length) == 0)) then
      anomaly(
        "closed_bead_missing_validation_evidence";
        "fail_closed";
        [events("bead_state")[0].event_id // ""];
        "Closed bead lacks linked validation command evidence";
        "Attach deterministic validation command evidence before accepting the closeout"
      )
    else empty end),
    (if root_fail("ack_required_message_unacknowledged") or any(events("mail_message")[]?; (.payload.ack_required // false) == true and (((.payload.ack_ts // .payload.acknowledged_at // .payload.acknowledged_at_utc // "") | length) == 0) and ((.payload.acknowledged // false) != true)) then
      anomaly(
        "ack_required_message_unacknowledged";
        "fail_closed";
        [events("mail_message")[]? | select((.payload.ack_required // false) == true) | .event_id];
        "ack_required Agent Mail message lacks acknowledgement evidence";
        "Acknowledge the coordination message or record why it is stale before accepting the trace"
      )
    else empty end),
    (if root_fail("stale_owner_recent_activity_conflict") or (((bead_state.payload.assignee // "") != "") and ((bead_state.payload.assignee // "") != $agent_name) and (((bead_state.payload.status // "") == "in_progress") or ((bead_state.payload.status // "") == "closed"))) then
      anomaly(
        "stale_owner_recent_activity_conflict";
        "fail_closed";
        [events("bead_state")[0].event_id // ""];
        "Bead owner or recent activity conflicts with the tracing agent";
        "Resolve bead ownership and reservation activity before accepting the handoff"
      )
    else empty end)
  ]
  | sort_by(.anomaly_class, .detail)
  | unique_by(.anomaly_class)
  | .[]
' "$normalized_events_json" >"$raw_anomalies_jsonl"
hash_jsonl_rows "$raw_anomalies_jsonl" "$anomalies_jsonl" "anomaly_hash"

anomaly_count="$(jq -s 'length' "$anomalies_jsonl")"
fail_closed_count="$(jq -s '[.[] | select(.severity == "fail_closed")] | length' "$anomalies_jsonl")"
degraded_count="$(jq -s '[.[] | select(.severity == "degraded")] | length' "$anomalies_jsonl")"
graph_decision="$event_set_decision"
if [[ "$fail_closed_count" -gt 0 || "$event_set_decision" == "fail_closed" ]]; then
  graph_decision="fail_closed"
elif [[ "$degraded_count" -gt 0 || "$event_set_decision" == "degraded" ]]; then
  graph_decision="degraded"
fi

jq -n \
  --arg bead_id "$bead_id" \
  --arg agent_name "$agent_name" \
  --arg source_revision "$source_revision" \
  --arg trace_id "$trace_id" \
  --arg normalized_events_json "$normalized_events_json" \
  --arg anomaly_report_json "$anomaly_report_path" \
  --arg decision "$graph_decision" \
  --argjson anomaly_count "$anomaly_count" \
  --argjson fail_closed_count "$fail_closed_count" \
  --argjson degraded_count "$degraded_count" \
  --slurpfile anomalies "$anomalies_jsonl" \
  '{
    schema_version:"franken-engine.swarm-agent-causal-trace-anomaly-report.v1",
    trace_id:$trace_id,
    bead_id:$bead_id,
    agent_name:$agent_name,
    source_revision:$source_revision,
    decision:$decision,
    anomaly_count:$anomaly_count,
    fail_closed_count:$fail_closed_count,
    degraded_count:$degraded_count,
    anomaly_classes:($anomalies | map(.anomaly_class) | sort),
    anomalies:$anomalies,
    artifact_paths:{
      normalized_events_json:$normalized_events_json,
      anomaly_report_json:$anomaly_report_json
    }
  }' >"$anomaly_report_tmp"
mv "$anomaly_report_tmp" "$anomaly_report_path"

jq -n \
  --arg trace_id "$trace_id" \
  --arg bead_id "$bead_id" \
  --arg agent_name "$agent_name" \
  --arg source_revision "$source_revision" \
  --arg normalized_events_json "$normalized_events_json" \
  --arg causal_graph_json "$graph_path" \
  --arg anomaly_report_json "$anomaly_report_path" \
  --arg events_jsonl "$events_path" \
  --arg commands_txt "$commands_path" \
  --arg report_md "$report_path" \
  --arg decision "$graph_decision" \
  --argjson anomaly_count "$anomaly_count" \
  --argjson fail_closed_count "$fail_closed_count" \
  --argjson degraded_count "$degraded_count" \
  --slurpfile nodes "$nodes_jsonl" \
  --slurpfile edges "$edges_jsonl" \
  --slurpfile anomalies "$anomalies_jsonl" \
  '{
    schema_version:"franken-engine.swarm-agent-causal-trace-graph.v1",
    trace_id:$trace_id,
    bead_id:$bead_id,
    agent_name:$agent_name,
    source_revision:$source_revision,
    nodes:($nodes | sort_by(.node_id)),
    edges:($edges | sort_by(.edge_id)),
    anomaly_summary:{
      decision:$decision,
      anomaly_count:$anomaly_count,
      fail_closed_count:$fail_closed_count,
      degraded_count:$degraded_count,
      anomaly_classes:($anomalies | map(.anomaly_class) | sort),
      anomaly_report_json:$anomaly_report_json
    },
    mutation_policy:{
      fixture_fed_only:true,
      mutates_br:false,
      reassigns_beads:false,
      releases_reservations:false,
      sends_agent_mail:false,
      queries_live_agent_mail:false,
      runs_cargo:false,
      runs_rch:false,
      mutates_remote_workers:false,
      changes_live_queue_policy:false,
      rewrites_historical_outcomes:false,
      operator_wording_required:"advisory-only"
    },
    artifact_paths:{
      normalized_events_json:$normalized_events_json,
      causal_graph_json:$causal_graph_json,
      anomaly_report_json:$anomaly_report_json,
      events_jsonl:$events_jsonl,
      commands_txt:$commands_txt,
      report_md:$report_md
    }
  }' >"$graph_tmp"
mv "$graph_tmp" "$graph_path"

{
  printf '# Swarm Agent Causal Trace Graph\n\n'
  printf -- "- Decision: \`%s\`\n" "$graph_decision"
  printf -- "- Bead: \`%s\`\n" "$bead_id"
  printf -- "- Agent: \`%s\`\n" "$agent_name"
  printf -- "- Nodes: \`%s\`\n" "$(jq '.nodes | length' "$graph_path")"
  printf -- "- Edges: \`%s\`\n" "$(jq '.edges | length' "$graph_path")"
  printf -- "- Anomalies: \`%s\`\n" "$anomaly_count"
  printf -- "- Fail-closed anomalies: \`%s\`\n" "$fail_closed_count"
} >"$report_path"

emit_event "graph_complete" "$graph_decision"
printf 'swarm_agent_causal_trace_graph=%s\n' "$graph_path"
printf 'swarm_agent_causal_trace_anomalies=%s\n' "$anomaly_report_path"

if [[ "$graph_decision" == "fail_closed" ]]; then
  exit 42
fi
